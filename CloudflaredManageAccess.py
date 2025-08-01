import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import subprocess
import os
import webbrowser
import urllib.request
import json
import shutil

import sys
def resource_path(relative_path):
    """
    Renvoie le chemin absolu vers une ressource, compatible avec les modes script et exécutable PyInstaller.

    Args:
        relative (str): Le chemin relatif vers la ressource.

    Returns:
        str: Le chemin absolu vers la ressource.
    """
    try:
        base_path = sys._MEIPASS  # utilisé par PyInstaller
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

APPDATA_DIR = os.path.join(os.getenv('APPDATA'), "CloudflaredManager")
os.makedirs(APPDATA_DIR, exist_ok=True)

CONFIG_FILE = os.path.join(APPDATA_DIR, "cloudflared_configs.json")
TOKENS_FILE = os.path.join(APPDATA_DIR, "cloudflared_tokens.json")

# print(CONFIG_FILE,TOKENS_FILE)
if os.path.isfile(CONFIG_FILE):
    PRESETS={}
else:
    PRESETS = {
  "MongoDB": {
    "hostname": "mongodb.tondomaine.fr",
    "host": "127.0.0.1",
    "port": "27017"},
  "SSH": {
    "hostname": "ssh.tondomaine.fr",
    "host": "127.0.0.1",
    "port": "22"}}

TOKENS = {}

class CloudflaredTab:
    def rename_profile(self):
        name = self.profile_var.get()
        if name not in PRESETS:
            return
        new_name = simpledialog.askstring("Renommer le profil", "Nouveau nom :", initialvalue=name)
        if new_name and new_name != name:
            PRESETS[new_name] = PRESETS.pop(name)
            self.profile_menu['values'] = list(PRESETS.keys())
            self.profile_var.set(new_name)
            with open(CONFIG_FILE, "w") as f:
                json.dump(PRESETS, f, indent=2)

    def delete_profile(self):
        name = self.profile_var.get()
        if name not in PRESETS:
            return
        confirm = messagebox.askyesno("Supprimer", f"Supprimer le profil '{name}' ?")
        if confirm:
            del PRESETS[name]
            self.profile_menu['values'] = list(PRESETS.keys())
            self.profile_var.set('')
            with open(CONFIG_FILE, "w") as f:
                json.dump(PRESETS, f, indent=2)

    def rename_token(self):
        name = self.token_profile_var.get()
        # print(name not in TOKENS)
        if name not in TOKENS:
            return
        new_name = simpledialog.askstring("Renommer le token", "Nouveau nom :", initialvalue=name)
        if new_name and new_name != name:
            TOKENS[new_name] = TOKENS.pop(name)
            self.token_menu['values'] = list(TOKENS.keys())
            self.token_profile_var.set(new_name)
            with open(TOKENS_FILE, "w") as f:
                json.dump(TOKENS, f, indent=2)

    def delete_token(self):
        name = self.token_profile_var.get()
        if name not in TOKENS:
            return
        confirm = messagebox.askyesno("Supprimer", f"Supprimer le token '{name}' ?")
        if confirm:
            del TOKENS[name]
            self.token_menu['values'] = list(TOKENS.keys())
            self.token_profile_var.set('')
            with open(TOKENS_FILE, "w") as f:
                json.dump(TOKENS, f, indent=2)
    def __init__(self, parent, cloudflared_path_var):
        self.frame = ttk.Frame(parent)
        self.cloudflared_path_var = cloudflared_path_var

        self.profile_var = tk.StringVar(value="Default")
        self.profile_menu = ttk.Combobox(self.frame, textvariable=self.profile_var, state="readonly")
        self.profile_menu.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        self.profile_menu.bind("<<ComboboxSelected>>", self.load_profile)

        self.import_btn = ttk.Button(self.frame, text="Importer", command=self.import_config)
        self.import_btn.grid(row=0, column=1, padx=2, sticky='ew')

        self.save_btn = ttk.Button(self.frame, text="Enregistrer", command=self.save_config)
        self.save_btn.grid(row=0, column=2, padx=(0, 2), sticky='ew')

        self.new_profile_btn = ttk.Button(self.frame, text="➕", width=3, command=self.create_new_profile)
        self.new_profile_btn.grid(row=0, column=3, padx=(0, 5), sticky='ew')

        self.rename_profile_btn = ttk.Button(self.frame, text="✏️", width=3, command=self.rename_profile)
        self.rename_profile_btn.grid(row=0, column=4, padx=(0, 2), sticky='ew')
        self.delete_profile_btn = ttk.Button(self.frame, text="🗑️", width=3, command=self.delete_profile)
        self.delete_profile_btn.grid(row=0, column=5, padx=(0, 5), sticky='w')

        ttk.Label(self.frame, text="Tokens :").grid(row=0, column=6, sticky="e")
        self.token_profile_var = tk.StringVar(value="")
        self.token_menu = ttk.Combobox(self.frame, textvariable=self.token_profile_var, state="readonly")
        self.token_menu.grid(row=0, column=7, sticky="ew", padx=2)
        self.token_menu.bind("<<ComboboxSelected>>", self.load_token_profile)

        ttk.Button(self.frame, text="Importer Token", command=self.import_tokens).grid(row=0, column=8, padx=2, sticky='ew')
        ttk.Button(self.frame, text="Enregistrer Token", command=self.save_token).grid(row=0, column=9, padx=2, sticky='ew')
        ttk.Button(self.frame, text="➕", width=3, command=self.create_new_token_profile).grid(row=0, column=10, padx=(0, 5), sticky='w')
        self.rename_token_btn = ttk.Button(self.frame, text="✏️", width=3, command=self.rename_token)
        self.rename_token_btn.grid(row=0, column=11, padx=(0, 2), sticky='ew')
        self.delete_token_btn = ttk.Button(self.frame, text="🗑️", width=3, command=self.delete_token)
        self.delete_token_btn.grid(row=0, column=12, padx=(0, 5), sticky='w')

        ttk.Label(self.frame, text="Hostname :").grid(row=1, column=0, sticky="e")
        self.hostname_entry = ttk.Entry(self.frame)
        self.hostname_entry.grid(row=1, column=1, columnspan=8, sticky="ew", padx=5, pady=5)

        ttk.Label(self.frame, text="Hôte local :").grid(row=2, column=0, sticky="e")
        self.host_entry = ttk.Entry(self.frame)
        self.host_entry.grid(row=2, column=1, sticky="ew", padx=5, pady=5)

        ttk.Label(self.frame, text="Port :").grid(row=2, column=2, sticky="e")
        self.port_entry = ttk.Entry(self.frame, width=10)
        self.port_entry.grid(row=2, column=3, sticky="w", padx=5, pady=5)

        self.use_token_var = tk.BooleanVar()
        self.use_token_check = ttk.Checkbutton(self.frame, text="Utiliser un Service Token", variable=self.use_token_var, command=self.toggle_token_fields)
        self.use_token_check.grid(row=3, columnspan=9, sticky="w", padx=5)

        ttk.Label(self.frame, text="Token ID :").grid(row=4, column=0, sticky="e")
        self.token_id_entry = ttk.Entry(self.frame, state="disabled")
        self.token_id_entry.grid(row=4, column=1, columnspan=8, sticky="ew", padx=5, pady=5)

        ttk.Label(self.frame, text="Token Secret :").grid(row=5, column=0, sticky="e")
        self.token_secret_entry = ttk.Entry(self.frame, state="disabled")
        self.token_secret_entry.grid(row=5, column=1, columnspan=8, sticky="ew", padx=5, pady=5)

        self.launch_button = ttk.Button(self.frame, text="Lancer la connexion", command=self.run_cloudflared)
        self.launch_button.grid(row=6,column=0, columnspan=9, pady=10)

        self.close_button = ttk.Button(self.frame, text="❌ Fermer connexion", command=self.close_connection)
        self.close_button.grid(row=6,column=1, columnspan=9, pady=5)

        for i in range(9):
            match i:
                case i if i > 1 and i < 6:
                    pass
                case _:
                    # print(i)
                    self.frame.columnconfigure(i, weight=1)

    def toggle_token_fields(self):
        """
        Active ou désactive les champs d'entrée des tokens en fonction de la case à cocher 'Utiliser un Service Token'.
        """
        state = "normal" if self.use_token_var.get() else "disabled"
        self.token_id_entry.configure(state=state)
        self.token_secret_entry.configure(state=state)
        if state == "disabled":
            self.token_id_entry.delete(0, tk.END)
            self.token_secret_entry.delete(0, tk.END)

    def create_new_profile(self):
        """
        Crée un nouveau profil de connexion en demandant un nom via une boîte de dialogue, puis l'ajoute à la liste déroulante.
        """
        name = simpledialog.askstring("Nouveau profil", "Nom du nouveau profil :")
        if name and name not in PRESETS:
            PRESETS[name] = {}
            self.profile_menu['values'] = list(PRESETS.keys())
            self.profile_var.set(name)

    def create_new_token_profile(self):
        """
        Crée un nouveau profil de token vide après avoir demandé un nom, puis l'ajoute à la liste déroulante.
        """
        name = simpledialog.askstring("Nouveau token", "Nom du nouveau token :")
        if name and name not in TOKENS:
            TOKENS[name] = {"token_id": "", "token_secret": ""}
            self.token_menu['values'] = list(TOKENS.keys())
            self.token_profile_var.set(name)

    def load_profile(self, event=None):
        """
        Charge les paramètres d'un profil sélectionné (hostname, hôte local, port, token) dans les champs de l'interface.

        Args:
            event: (Optionnel) Événement Tkinter, ignoré.
        """
        name = self.profile_var.get()
        config = PRESETS.get(name, {})
        self.hostname_entry.delete(0, tk.END)
        self.hostname_entry.insert(0, config.get("hostname", ""))
        self.host_entry.delete(0, tk.END)
        self.host_entry.insert(0, config.get("host", "127.0.0.1"))
        self.port_entry.delete(0, tk.END)
        self.port_entry.insert(0, config.get("port", ""))
        self.token_id_entry.delete(0, tk.END)
        self.token_id_entry.insert(0, config.get("token_id", ""))
        self.token_secret_entry.delete(0, tk.END)
        self.token_secret_entry.insert(0, config.get("token_secret", ""))

    def load_token_profile(self, event=None):
        """
        Charge les informations d’un profil de token sélectionné (ID et secret), et active les champs associés.

        Args:
            event: (Optionnel) Événement Tkinter, ignoré.
        """
        name = self.token_profile_var.get()
        if not name:
            return
        self.use_token_var.set(True)
        self.toggle_token_fields()
        token = TOKENS.get(name, {})
        self.token_id_entry.delete(0, tk.END)
        self.token_id_entry.insert(0, token.get("token_id", ""))
        self.token_secret_entry.delete(0, tk.END)
        self.token_secret_entry.insert(0, token.get("token_secret", ""))

    def save_config(self):
        """
        Sauvegarde le profil de connexion courant dans le fichier JSON de configuration.
        Affiche une boîte d'information à la fin.
        """
        name = self.profile_var.get()
        if not name:
            return
        PRESETS[name] = {
            "hostname": self.hostname_entry.get(),
            "host": self.host_entry.get(),
            "port": self.port_entry.get(),
            "token_id": self.token_id_entry.get(),
            "token_secret": self.token_secret_entry.get()
        }
        with open(CONFIG_FILE, "w") as f:
            json.dump(PRESETS, f, indent=2)
        self.profile_menu['values'] = list(PRESETS.keys())
        timed_messagebox("Sauvegarde", f"Configuration '{name}' enregistrée.")

    def save_token(self):
        """
        Sauvegarde le profil de token courant dans le fichier JSON dédié.
        Affiche une boîte d'information à la fin.
        """
        name = self.token_profile_var.get()
        if not name:
            return
        TOKENS[name] = {
            "token_id": self.token_id_entry.get(),
            "token_secret": self.token_secret_entry.get()
        }
        with open(TOKENS_FILE, "w") as f:
            json.dump(TOKENS, f, indent=2)
        self.token_menu['values'] = list(TOKENS.keys())
        timed_messagebox("Sauvegarde", f"Token '{name}' enregistré.")

    def import_config(self):
        """
        Importe un fichier JSON contenant des profils de configuration cloudflared.
        Met à jour la liste des profils et sauvegarde dans le fichier local.
        """
        file_path = filedialog.askopenfilename(title="Importer un fichier de profils", filetypes=[("Fichiers JSON", "*.json")])
        if not file_path:
            return
        with open(file_path, "r") as f:
            loaded = json.load(f)
            PRESETS.update(loaded)
            self.profile_menu['values'] = list(PRESETS.keys())
            imported_names = ', '.join(loaded.keys())
            with open(CONFIG_FILE, "w") as f_config:
                json.dump(PRESETS, f_config, indent=2)
            timed_messagebox("Import", f"Configurations importées : {imported_names}")
            self.profile_menu['values'] = list(PRESETS.keys())
            messagebox.showinfo("Import", "Configurations importées.")

    def import_tokens(self):
        """
        Importe un fichier JSON contenant des tokens.
        Met à jour la liste des tokens et sauvegarde dans le fichier local.
        """
        file_path = filedialog.askopenfilename(title="Importer un fichier de tokens", filetypes=[("Fichiers JSON", "*.json")])
        if not file_path:
            return
        with open(file_path, "r") as f:
            loaded = json.load(f)
            TOKENS.update(loaded)
            self.token_menu['values'] = list(TOKENS.keys())
            imported_names = ', '.join(loaded.keys())
            with open(TOKENS_FILE, "w") as f_tokens:
                json.dump(TOKENS, f_tokens, indent=2)
            messagebox.showinfo("Import", f"Tokens importés : {imported_names}")
            self.token_menu['values'] = list(TOKENS.keys())
            messagebox.showinfo("Import", "Tokens importés.")

    def close_connection(self):
        if not cloudflared_processes:
            timed_messagebox("Erreur", "Aucune connexion active à fermer.")
            return

        def confirm_and_close(index):
            proc = cloudflared_processes.pop(index)
            if '--hostname' in proc.args:
                hostname_index = proc.args.index('--hostname') + 1
                hostname = proc.args[hostname_index]
                # print(f"Hostname : {hostname}")
                timed_messagebox("Connexion fermée", f"Connexion {hostname} arrêtée.")
            else:
                timed_messagebox("Connexion fermée", f"Connexion UNKNOWN arrêtée.")
            proc.terminate()
            update_connection_status()
            try:
                dialog.destroy()
            except Exception as e:
                pass
        if len(cloudflared_processes) == 1:
            confirm_and_close(0)
        else:
            dialog = tk.Toplevel()
            dialog.title("Fermer une connexion")
            dialog.geometry("500x260")
            ttk.Label(dialog, text="Sélectionnez une connexion à fermer :").pack(pady=10)
            listbox = tk.Listbox(dialog, width=80)
            listbox.pack(padx=10, pady=5, fill="both", expand=True)
            for i, p in enumerate(cloudflared_processes):
                hostname = next((arg for j, arg in enumerate(p.args) if p.args[j-1] == '--hostname'), f"Connexion {i}")
                listbox.insert(tk.END, f"{hostname}")

            def on_select():
                selected = listbox.curselection()
                if selected:
                    confirm_and_close(selected[0])

            ttk.Button(dialog, text="Fermer la connexion sélectionnée", command=on_select).pack(pady=10)
            dialog.attributes('-topmost', True)
            dialog.grab_set()
        update_connection_status()

    def run_cloudflared(self):
        import socket
        host = self.host_entry.get().strip() or "127.0.0.1"
        port = self.port_entry.get().strip()
        if not port.isdigit():
            timed_messagebox("Erreur", "Le port spécifié n'est pas valide.")
            return
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, int(port)))
            except OSError:
                timed_messagebox("Port utilisé", f"Le port {port} est déjà utilisé localement. Veuillez en choisir un autre.")
                return
        for proc in cloudflared_processes:
            if proc.args and f"--url {self.host_entry.get()}:{self.port_entry.get()}" in ' '.join(proc.args):
                timed_messagebox("Erreur", f"Une connexion est déjà active sur le port {self.port_entry.get()}. Veuillez en choisir un autre.")
                return
        """
        Lance la commande cloudflared avec les paramètres fournis par l'utilisateur.
        Gère l'utilisation ou non d'un token.
        Affiche une boîte de dialogue en cas d’erreur ou de succès.
        """
        path = self.cloudflared_path_var.get()
        if not path or not os.path.isfile(path):
            timed_messagebox("Erreur", "Chemin vers cloudflared non valide.")
            return

        hostname = self.hostname_entry.get().strip()
        host = self.host_entry.get().strip() or "127.0.0.1"
        port = self.port_entry.get().strip()
        if not hostname or not port:
            messagebox.showerror("Erreur", "Hostname et Port doivent être renseignés.")
            return

        cmd = [path, "access", "tcp", "--hostname", hostname, "--url", f"{host}:{port}"]

        if self.use_token_var.get():
            token_id = self.token_id_entry.get().strip()
            token_secret = self.token_secret_entry.get().strip()
            if not token_id or not token_secret:
                messagebox.showerror("Erreur", "Token ID et Secret doivent être renseignés.")
                return
            cmd += ["--service-token-id", token_id, "--service-token-secret", token_secret]

        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo)
            cloudflared_processes.append(proc)
            try:
                _, stderr = proc.communicate(timeout=1)
                if b"address already in use" in stderr:
                    timed_messagebox("Port utilisé", f"Le port {port} est déjà utilisé. Veuillez en choisir un autre.")
                    proc.terminate()
                    return
            except subprocess.TimeoutExpired:
                pass
            timed_messagebox("Succès", f"Connexion vers {hostname} lancée.")
            update_connection_status()
        except Exception as e:
            messagebox.showerror("Erreur", f"Échec d'exécution : {e}")

class CloudflaredGUI:
    def __init__(self, root):  # Main GUI initialization
        """
        Initialise l'interface principale, charge les profils, configure les onglets et les boutons.
        
        Args:
            root (tk.Tk): Fenêtre principale Tkinter.
        """
        self.root = root
        self.root.title("Gestionnaire Cloudflared TCP Tunnel")
        self.cloudflared_path_var = tk.StringVar()

        # Charger les profils AVANT d'ajouter des onglets
        self.load_configs_and_tokens()
        self.load_saved_cloudflared_path()
        self.detect_cloudflared()

        self.top_frame = ttk.Frame(root)
        self.top_frame.pack(fill="x", pady=5)

        ttk.Label(self.top_frame, text="cloudflared.exe :").pack(side="left", padx=5)
        self.path_entry = ttk.Entry(self.top_frame, textvariable=self.cloudflared_path_var, width=50)
        self.path_entry.pack(side="left", padx=5)

        ttk.Button(self.top_frame, text="Parcourir", command=self.browse_exe).pack(side="left", padx=5)
        ttk.Button(self.top_frame, text="Téléchargement direct", command=self.download_cloudflared).pack(side="left")
        ttk.Button(self.top_frame, text="Page Cloudflare", command=self.open_download_page).pack(side="left")

        self.tab_control = ttk.Notebook(root)
        self.tab_control.pack(expand=1, fill="both")

        self.button_frame = ttk.Frame(root)
        self.button_frame.pack(pady=5)

        ttk.Button(self.button_frame, text="Nouvel onglet", command=self.add_tab).pack(side="left", padx=5)
        ttk.Button(self.button_frame, text="Supprimer l'onglet courant", command=self.remove_current_tab).pack(side="left", padx=5)

        self.tabs = []
        self.tab_count = 0
        self.add_tab()

        self.status_label = ttk.Label(root, text="Connexions ouvertes : 0", anchor="e")
        self.status_label.pack(side="bottom", fill="x", padx=5, pady=2)

    def detect_cloudflared(self):
        """
        Tente de détecter automatiquement le chemin vers l'exécutable cloudflared via la variable d’environnement PATH.
        """
        path = shutil.which("cloudflared")
        if path:
            self.cloudflared_path_var.set(path)

    def browse_exe(self):
        """
        Ouvre une boîte de dialogue pour sélectionner manuellement le fichier cloudflared.exe.
        Sauvegarde ensuite le chemin dans un fichier JSON.
        """
        path = filedialog.askopenfilename(title="Sélectionner cloudflared.exe", filetypes=[("Executable", "*.exe")])
        if path:
            self.cloudflared_path_var.set(path)
            self.save_cloudflared_path(path)

    def download_cloudflared(self):
        """
        Télécharge automatiquement l’exécutable cloudflared depuis GitHub.
        Demande où l’enregistrer via une boîte de dialogue.
        """
        save_path = filedialog.asksaveasfilename(defaultextension=".exe", filetypes=[("Executable", "*.exe")], title="Enregistrer cloudflared.exe")
        if not save_path:
            return
        url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
        try:
            urllib.request.urlretrieve(url, save_path)
            self.cloudflared_path_var.set(save_path)
            messagebox.showinfo("Téléchargement terminé", f"cloudflared.exe téléchargé à :\n{save_path}")
        except Exception as e:
            messagebox.showerror("Erreur de téléchargement", f"Impossible de télécharger : {e}")

    def load_configs_and_tokens(self):
        """
        Charge les fichiers JSON existants contenant les profils et les tokens.
        Met à jour les variables globales `PRESETS` et `TOKENS`.
        """
        global PRESETS, TOKENS
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                PRESETS.update(json.load(f))
        if os.path.exists(TOKENS_FILE):
            with open(TOKENS_FILE, "r") as f:
                TOKENS.update(json.load(f))

    def save_cloudflared_path(self, path):
        """
        Sauvegarde le chemin vers cloudflared dans un fichier JSON.

        Args:
            path (str): Chemin absolu vers l’exécutable cloudflared.
        """
        save_file = os.path.join(APPDATA_DIR, "cloudflared_path.json")
        with open(save_file, "w") as f:
            json.dump({"path": path}, f)

    def load_saved_cloudflared_path(self):
        """
        Charge le chemin précédemment sauvegardé vers cloudflared depuis le fichier JSON.
        """
        save_file = os.path.join(APPDATA_DIR, "cloudflared_path.json")
        if os.path.exists(save_file):
            with open(save_file, "r") as f:
                data = json.load(f)
                self.cloudflared_path_var.set(data.get("path", ""))

    def open_download_page(self):
        """
        Ouvre la page officielle de téléchargement de cloudflared dans le navigateur par défaut.
        """
        webbrowser.open("https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/")

    def add_tab(self):
        """
        Ajoute un nouvel onglet de configuration (nouvelle instance de CloudflaredTab) à l’interface.
        """
        self.tab_count += 1
        tab = CloudflaredTab(self.tab_control, self.cloudflared_path_var)
        tab.profile_menu['values'] = list(PRESETS.keys())
        tab.token_menu['values'] = list(TOKENS.keys())
        self.tabs.append(tab)
        self.tab_control.add(tab.frame, text=f"Connexion {self.tab_count}")
        self.tab_control.select(len(self.tabs) - 1)

    def remove_current_tab(self):
        """
        Supprime l’onglet actuellement sélectionné si plus d’un onglet est présent.
        Affiche une alerte si l'utilisateur tente de supprimer le dernier onglet.
        """
        if len(self.tabs) <= 1:
            messagebox.showinfo("Impossible", "Impossible de supprimer le dernier onglet.")
            return
        current = self.tab_control.index(self.tab_control.select())
        self.tab_control.forget(current)
        del self.tabs[current]

import signal
import psutil
import atexit

cloudflared_processes = []
connection_labels = []

def timed_messagebox(title, message, duration=10000):
    top = tk.Toplevel()
    top.title(title)
    top.geometry("400x100")
    tk.Label(top, text=message, wraplength=380, justify="left").pack(padx=10, pady=10)
    top.after(duration, top.destroy)
    top.attributes('-topmost', True)
    top.grab_set()


def update_connection_status():
    status_text = f"Connexions ouvertes : {len(cloudflared_processes)}"
    if hasattr(app, 'status_label'):
        app.status_label.config(text=status_text)


def cleanup():
    for proc in cloudflared_processes:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

atexit.register(cleanup)

if __name__ == "__main__":
    root = tk.Tk()
    root.iconbitmap(resource_path("cloudflared.ico"))
    app = CloudflaredGUI(root)
    root.mainloop()
