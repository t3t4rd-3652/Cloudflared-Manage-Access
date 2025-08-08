# Cloudflared Manage Access
CMA est une interface graphique portable (Tkinter) pour simplifier la gestion de la connexion client aux différents tunnels TCP cloudflared access.

🎯 Fonctionnalités principales :

🔍 Détection automatique de cloudflared dans le PATH

📂 Sélection manuelle du binaire cloudflared.exe si nécessaire

🌐 Connexion rapide à un hostname via --url local

🔐 Support des Service Token ID / Secret

🗂️ Interface à onglets multiples pour gérer plusieurs connexions

📦 Préconfigurations intégrées : MongoDB, SSH, etc.

💾 Enregistrement / import de profils personnalisés (JSON)

🧳 100 % portable : aucune installation nécessaire, les fichiers restent locaux

Permet également de faire la gestion ainsi que la redirection de ports via une connexion SSH.

> 🚀 Exécution via python

>> python CloudflaredManageAccess.py

Le .exe est également disponible dans \dist

> 📚 Compilation

>> python -m PyInstaller --onefile --windowed --hidden-import=tkinter --hidden-import=tkinter.filedialog --icon=cloudflared.ico --add-data "cloudflared.ico;." CloudflaredManageAccess.py 

📦 Dépendances
Python >= 3.13.5

Aucun package externe requis (Tkinter est natif)
