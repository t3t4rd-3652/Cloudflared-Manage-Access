# Licences des composants tiers

Cloudflared Manage Access est distribué sous licence MIT (voir [LICENSE.md](LICENSE.md)).
La distribution Windows embarque les composants suivants.

| Composant | Licence | Usage |
| --- | --- | --- |
| [Qt 6](https://www.qt.io/) via [PySide6](https://doc.qt.io/qtforpython-6/) | LGPL-3.0 | Interface graphique. Livré en bibliothèques dynamiques (mode onedir) : elles peuvent être remplacées par une autre version compatible. Sources : <https://code.qt.io/> |
| [asyncssh](https://github.com/ronf/asyncssh) | EPL-2.0 ou GPL-2.0+ | Connexions SSH, SFTP, clés |
| [cryptography](https://github.com/pyca/cryptography) | Apache-2.0 ou BSD-3-Clause | Primitives cryptographiques (utilisée par asyncssh et le chiffrement des exports) |
| [bcrypt](https://github.com/pyca/bcrypt) | Apache-2.0 | Clés OpenSSH chiffrées par phrase de passe |
| [keyring](https://github.com/jaraco/keyring) | MIT | Accès au coffre du système |
| [pywin32-ctypes](https://github.com/enthought/pywin32-ctypes) | BSD-3-Clause | Gestionnaire d'identifiants Windows (keyring) |
| [pydantic](https://github.com/pydantic/pydantic) | MIT | Modèles et validation |
| [Tabler Icons](https://tabler.io/icons) | MIT | Icônes de l'interface (`src/cma/resources/icons`, licence dans `LICENSE-tabler.txt`) |
| [Python](https://www.python.org/) | PSF-2.0 | Environnement d'exécution |
| [OpenSSL](https://www.openssl.org/) | Apache-2.0 | Livré avec Python et cryptography |

`cloudflared` n'est pas inclus : il est détecté sur le poste ou téléchargé depuis les releases officielles de
Cloudflare (licence Apache-2.0).

Outils de développement, non distribués : pytest, pytest-qt, pytest-asyncio, pytest-cov, ruff, pyright, PyInstaller,
Inno Setup, paramiko (banc d'essai uniquement).
