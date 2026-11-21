# Scan2Shell

Pipeline Python de reconnaissance et de suggestion d'exploit : scan de ports/services, recherche croisée de vulnérabilités (Exploit-DB + NVD), et filtrage de pertinence par produit et version.

> ⚠️ Usage académique uniquement, sur des cibles dont vous êtes propriétaire ou explicitement autorisé à tester (ex. Metasploitable2, DVWA, votre propre homelab).

## Fonctionnement

```
Scan Nmap (-sV)  →  Recherche de vulnérabilités  →  Filtrage de pertinence  →  Rapport JSON
                     (searchsploit + API NVD)        (produit + version)
```

1. **Scan** : identification des ports ouverts et des services exposés via `python-nmap`.
2. **Recherche de vulnérabilités** : pour chaque service détecté, interrogation de `searchsploit` (base Exploit-DB locale) et de l'API NVD (CVE officielles, avec score CVSS quand disponible).
3. **Filtrage de pertinence** : élimination des résultats dont le titre ne correspond ni au produit détecté, ni à une plage de version compatible, pour réduire le bruit.
4. **Rapport** : résumé affiché en console et export JSON structuré.

## Prérequis

```bash
sudo apt install nmap exploitdb
sudo searchsploit -u
pip install python-nmap requests
```

Une clé API NVD est optionnelle mais recommandée (évite le rate limit de 5 requêtes/30s sans clé).

## Utilisation

```bash
sudo python3 main.py <IP_cible>

# Options
sudo python3 main.py <IP_cible> --ports 1-65535
sudo python3 main.py <IP_cible> --udp
sudo python3 main.py <IP_cible> --nvd-key TA_CLE_API
sudo python3 main.py <IP_cible> --output rapport.json
```

`sudo` est nécessaire car la détection de version (`-sV`) et certaines options Nmap requièrent des privilèges élevés.

## Exemple de résultat (Metasploitable2)

```
Port 21/tcp — ftp vsftpd 2.3.4
  [searchsploit] vsftpd 2.3.4 - Backdoor Command Execution (Metasploit) -> .../17491.rb
  [nvd] CVE-2011-2523 (CVSS 9.8) -> CVE-2011-2523

Port 139/tcp — netbios-ssn Samba smbd 3.X - 4.X
  [searchsploit] Samba 3.0.20 < 3.0.25rc3 - 'Username map script' Command Execution (Metasploit) -> .../16320.rb
```

Ces deux résultats correspondent à des vulnérabilités connues et documentées (backdoor vsftpd, `usermap_script` Samba), utilisées ici comme validation du pipeline.

## Limitations connues

- **Versions imprécises** : lorsque Nmap ne détecte qu'une plage de version (ex. `3.X - 4.X` pour Samba), le filtrage de version est désactivé et seul le filtrage par nom de produit s'applique — le volume de résultats remonte alors, avec davantage de faux positifs.
- **Correspondance par mot-clé** : le filtrage par produit vérifie la présence d'un mot du nom de produit dans le titre de l'exploit, ce qui peut laisser passer des résultats pour un produit au nom proche mais différent (ex. "Sambar Server" face à "Samba").
- **Pas de suggestion automatique de module Metasploit** : l'outil indique les CVE et références Exploit-DB, mais ne propose pas encore de correspondance directe vers un module `msfconsole`.
- **Rate limit NVD** : sans clé API, les requêtes NVD sont espacées de 6 secondes, ce qui ralentit le scan sur les hôtes à nombreux services.

## Pistes d'amélioration

- Normalisation plus fine des noms de produits (table de correspondance manuelle pour les cas ambigus).
- Intégration d'une recherche RPC Metasploit pour suggérer directement un module exploitable.
- Scoring de pertinence pondéré (plutôt qu'un filtre binaire) pour classer les résultats par probabilité de correspondance.

## Avertissement

Cet outil est destiné à un usage pédagogique et à des tests sur des environnements autorisés. Toute utilisation sur un système sans autorisation explicite est illégale.