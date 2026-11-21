#!/usr/bin/env python3
"""
Scan2Shell — Pipeline de reconnaissance : scan Nmap -> recherche de CVE -> suggestion d'exploit
Usage académique / environnements autorisés uniquement.
"""

import re
import json
import time
import argparse
import subprocess
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Tuple

import nmap
import requests


# ---------- Structures de données ----------

@dataclass
class Exploit:
    source: str
    title: str
    ref: str
    cvss_score: Optional[float] = None


@dataclass
class ServiceResult:
    port: int
    protocol: str
    service: str
    product: str
    version: str
    exploits: List[Exploit] = field(default_factory=list)


# ---------- 1. Scan Nmap ----------

def scan_target(target: str, ports: str = "1-1000", udp: bool = False) -> List[ServiceResult]:
    scanner = nmap.PortScanner()
    arguments = f"-sV -p {ports}"
    if udp:
        arguments += " -sU"

    print(f"[*] Scan de {target} ({arguments})...")
    scanner.scan(hosts=target, arguments=arguments)

    results = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port, data in scanner[host][proto].items():
                if data["state"] != "open":
                    continue
                results.append(ServiceResult(
                    port=port,
                    protocol=proto,
                    service=data.get("name", ""),
                    product=data.get("product", ""),
                    version=data.get("version", ""),
                ))
    return results


# ---------- 2. Filtrage de pertinence (produit + version) ----------

def is_product_relevant(title: str, product: str) -> bool:
    """Vérifie qu'au moins un mot significatif du produit apparaît dans le titre."""
    if not product:
        return True
    keywords = [w.lower() for w in re.findall(r'[A-Za-z]{3,}', product)]
    if not keywords:
        return True
    title_lower = title.lower()
    return any(kw in title_lower for kw in keywords)


def extract_version_bounds(title: str) -> Optional[Tuple[Optional[str], Optional[str]]]:
    """Extrait une borne de version du titre."""
    # Cas "X < Y" ou "< Y"
    match = re.search(r'(?:(\d+\.\d+(?:\s?p\d+)?)\s*)?<\s*(\d+\.\d+(?:\s?p\d+)?)', title)
    if match:
        return (match.group(1), match.group(2))

    # Cas wildcard "N.x" — une ou deux occurrences (ex: "3.x", "3.X - 4.X", "2.x/3.x")
    wildcards = re.findall(r'(\d+)\.[xX]\b', title)
    if len(wildcards) >= 2:
        low, high = wildcards[0], wildcards[-1]
        return (f"{low}.0", f"{high}.999")
    elif len(wildcards) == 1:
        major = wildcards[0]
        return (f"{major}.0", f"{major}.999")

    # Cas version unique mentionnée (ex: "9.8p1")
    match = re.search(r'\b(\d+\.\d+(?:\s?p\d+)?)\b', title)
    if match:
        return (match.group(1), match.group(1))

    return None


def version_tuple(v: str) -> tuple:
    """Convertit '9.8p1' en (9, 8, 1) pour comparaison."""
    nums = re.findall(r'\d+', v)
    return tuple(int(n) for n in nums) if nums else (0,)


def is_version_relevant(title: str, detected_version: str) -> bool:
    """Vérifie si l'exploit s'applique à la version détectée (ou une version proche)."""
    # Si Nmap lui-même ne donne qu'une plage incertaine (ex: "3.X - 4.X"),
    # on ne peut pas comparer fiablement : on ne filtre que par produit.
    if re.search(r'[xX]\b', detected_version) or re.search(r'\d+\.\w+\s*-\s*\d+', detected_version):
        return True

    bounds = extract_version_bounds(title)
    if not bounds:
        return True

    detected = version_tuple(detected_version)
    low, high = bounds

    if low and high and low != high:
        return version_tuple(low) <= detected < version_tuple(high)
    else:
        target = version_tuple(high or low)
        return detected[:1] == target[:1]


def is_relevant(title: str, product: str, version: str) -> bool:
    return is_product_relevant(title, product) and is_version_relevant(title, version)


# ---------- 3. Recherche via searchsploit ----------

def _run_searchsploit(query: str) -> List[Exploit]:
    try:
        output = subprocess.run(
            ["searchsploit", "--json", query],
            capture_output=True, text=True, timeout=15
        )
        data = json.loads(output.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return []

    return [
        Exploit(source="searchsploit", title=e.get("Title", ""), ref=e.get("Path", ""))
        for e in data.get("RESULTS_EXPLOIT", [])
    ]


def search_searchsploit(product: str, version: str) -> List[Exploit]:
    if not product:
        return []

    queries = [f"{product} {version}".strip(), product]
    first_word = product.split()[0] if product.split() else None
    if first_word and first_word not in queries:
        queries.append(first_word)

    for query in queries:
        exploits = _run_searchsploit(query)
        if exploits:
            relevant = [e for e in exploits if is_relevant(e.title, product, version)]
            return relevant if relevant else exploits[:3]
    return []


# ---------- 4. Recherche via l'API NVD ----------

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def search_nvd(product: str, version: str, api_key: Optional[str] = None) -> List[Exploit]:
    if not product:
        return []

    params = {"keywordSearch": f"{product} {version}".strip(), "resultsPerPage": 5}
    headers = {"apiKey": api_key} if api_key else {}

    try:
        resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException:
        return []

    exploits = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        metrics = cve.get("metrics", {})
        cvss_score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                cvss_score = metrics[key][0]["cvssData"]["baseScore"]
                break
        exploits.append(Exploit(
            source="nvd",
            title=cve_id,
            ref=cve_id,
            cvss_score=cvss_score,
        ))

    time.sleep(6 if not api_key else 0.6)
    return exploits


# ---------- 5. Pipeline principal ----------

def run_pipeline(target: str, ports: str, udp: bool, nvd_api_key: Optional[str]) -> List[ServiceResult]:
    services = scan_target(target, ports, udp)

    for svc in services:
        print(f"[*] Recherche de vulnérabilités pour {svc.service} {svc.product} {svc.version}...")
        svc.exploits.extend(search_searchsploit(svc.product, svc.version))
        svc.exploits.extend(search_nvd(svc.product, svc.version, nvd_api_key))

    return services


# ---------- 6. Sortie ----------

def export_json(services: List[ServiceResult], path: str = "scan2shell_report.json"):
    data = [asdict(s) for s in services]
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Rapport exporté : {path}")


def print_summary(services: List[ServiceResult]):
    for svc in services:
        print(f"\nPort {svc.port}/{svc.protocol} — {svc.service} {svc.product} {svc.version}")
        if not svc.exploits:
            print("  Aucun exploit trouvé.")
        for exp in svc.exploits:
            cvss = f" (CVSS {exp.cvss_score})" if exp.cvss_score else ""
            print(f"  [{exp.source}] {exp.title}{cvss} -> {exp.ref}")


# ---------- Entrée ----------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan2Shell — recon + recherche de vulnérabilités")
    parser.add_argument("target", help="Cible à scanner (IP ou hostname)")
    parser.add_argument("--ports", default="1-1000", help="Plage de ports (défaut: 1-1000)")
    parser.add_argument("--udp", action="store_true", help="Inclure un scan UDP")
    parser.add_argument("--nvd-key", default=None, help="Clé API NVD (optionnelle)")
    parser.add_argument("--output", default="scan2shell_report.json")
    args = parser.parse_args()

    results = run_pipeline(args.target, args.ports, args.udp, args.nvd_key)
    print_summary(results)
    export_json(results, args.output)