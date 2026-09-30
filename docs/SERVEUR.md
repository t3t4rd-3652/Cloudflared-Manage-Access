# Côté serveur : ports-report et helper Docker

La vue **Serveurs SSH** liste les ports TCP en écoute sur un serveur Linux. Ce document explique ce qui s'exécute
sur le serveur, ce qu'il faut (ou non) y installer, et comment le retirer.

## Rien à installer par défaut

À chaque « Lister les ports », CMA ouvre une session SSH et exécute :

```bash
bash -s -- --json      # le contenu de server/ports-report est envoyé par l'entrée standard
```

Le script n'est jamais copié sur le serveur : c'est toujours la version livrée avec l'application qui s'exécute.

Prérequis sur le serveur :

| Outil | Rôle | Obligatoire |
| --- | --- | --- |
| `bash` 4.3+ | exécution du script | oui (sinon repli sur `ss -tln`, liste simplifiée) |
| `ss` (iproute2) | ports en écoute | oui |
| `awk` | analyse de `ss` ; mawk, gawk ou busybox conviennent | oui |
| `getent` | nom du service associé au port | non |
| `curl` | détection HTTP/HTTPS et code de réponse | non |
| `docker` | nom des conteneurs qui publient le port | non |

Le script est testé sur Debian 13 (mawk), Ubuntu 24.04 (mawk) et Alpine 3.20 (busybox awk).

## Ce que le script fait

1. Lit les ports TCP en écoute (`ss -tln`) et leurs adresses d'écoute.
2. Retrouve le service (`getent services`) et le conteneur Docker qui publie le port.
3. Sonde chaque port en HTTPS puis en HTTP sur l'adresse où il écoute, avec des délais courts (32 sondes en parallèle).
4. Écrit une ligne JSON par port :

```json
{"v":2,"proto":"tcp","port":3000,"bind":["127.0.0.1"],"service":null,"container":"grafana","scheme":"https","http_code":302,"final_url":"https://127.0.0.1:3000/login"}
```

L'adresse d'écoute sert de cible à la redirection : un service qui n'écoute que sur une IP précise, ou sur le bridge
Docker, reste joignable.

Options utiles :

```text
ports-report --json            sortie JSON (utilisée par CMA 2)
ports-report                   sortie texte historique (CMA 1.x)
ports-report --no-web          sans sonde HTTP
ports-report --exclude 22,53   ports à ignorer (aussi : PORTS_REPORT_EXCLUDE=22,53)
ports-report --all             sans les exclusions par défaut (5355, 5357, 20241, 45475)
ports-report --version
```

## Serveurs Windows

Sur un serveur Windows avec OpenSSH Server, CMA le reconnaît tout seul : `echo %OS% $env:OS` répond
« Windows_NT » sous cmd.exe comme sous PowerShell. Il envoie alors `server/ports-report.ps1` à PowerShell
par l'entrée standard, toujours sans rien installer :

```text
powershell -NoProfile -NonInteractive -Command "& {[Console]::In.ReadToEnd() | Invoke-Expression}"
```

| Élément | Source |
| --- | --- |
| Ports en écoute | `Get-NetTCPConnection`, sinon `netstat -ano` |
| Service | service Windows du processus (Win32_Service), sinon nom du processus ; `http.sys` pour le PID 4 |
| Conteneur | `docker ps`, si Docker est installé |
| Web | sonde HTTPS puis HTTP en parallèle, 1,5 s au plus par port |

Compatible Windows PowerShell 5.1 (Windows Server 2016 et suivants) et PowerShell 7. Les ports RPC dynamiques
des processus système (au-delà de 49152) et 135, 139, 445, 5040, 5355, 5357 sont ignorés ; `-All` les garde.
Le script sert aussi à la main :

```text
powershell -NoProfile -File ports-report.ps1 [-NoWeb] [-All]
```

## Noms des conteneurs Docker sans droits docker

`docker ps` exige d'appartenir au groupe `docker`, ce qui équivaut à être root. Pour n'afficher que les noms et
ports publiés, le script sait passer par un helper en lecture seule, autorisé par une règle sudoers précise.

Installation, depuis une copie du dépôt sur le serveur :

```bash
sudo ./server/install.sh --user alice              # un ou plusieurs --user
sudo ./server/install.sh --user alice --user bob
```

Le script installe :

| Fichier | Contenu |
| --- | --- |
| `/usr/local/bin/ports-report` | le script (utile aux anciennes versions de CMA, ou en ligne de commande) |
| `/usr/local/sbin/ports-report-docker-ps` | `exec docker ps --format '{{.Names}} {{.Ports}}'`, propriété de root |
| `/etc/sudoers.d/ports-report-<utilisateur>` | `alice ALL=(root) NOPASSWD: /usr/local/sbin/ports-report-docker-ps`, validé par `visudo` |

La règle n'autorise que ce helper, sans argument. Les points des noms d'utilisateur sont remplacés par `_` dans le nom
du fichier, car sudo ignore les fichiers de `/etc/sudoers.d` qui contiennent un point.

Autres options :

```bash
sudo ./server/install.sh --no-docker                 # seulement ports-report
sudo ./server/install.sh --uninstall --user alice    # retire la règle d'alice
sudo ./server/install.sh --uninstall                 # retire tout
```

Le script est idempotent et refuse les fichiers en fins de ligne Windows (CRLF).

## Dépannage

| Symptôme | Cause probable |
| --- | --- |
| « bash est absent du serveur : liste simplifiée » | serveur sans bash (BusyBox minimal) : repli sur `ss` |
| « Noms des conteneurs Docker indisponibles » | utilisateur hors du groupe docker et helper non installé |
| Colonne Web vide | `curl` absent, ou sonde désactivée (« Sonder HTTP/HTTPS ») |
| `env: 'bash\r'` en lançant le script à la main | fichier copié avec des fins de ligne Windows : `sed -i 's/\r$//' ports-report` |
