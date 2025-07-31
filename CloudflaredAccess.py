import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import os
import webbrowser
import urllib.request
import json
import shutil

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "cloudflared_configs.json")
TOKENS_FILE = os.path.join(os.path.dirname(__file__), "cloudflared_tokens.json")

PRESETS = {
    "Default": {},
    "MongoDB": {
        "hostname": "mongodb.tondomaine.fr",
        "host": "127.0.0.1",
        "port": "27017"
    },
    "SSH": {
        "hostname": "ssh.tondomaine.fr",
        "host": "127.0.0.1",
        "port": "22"
    },
    "SERVICEWEB1": {
        "hostname": "web1.tondomaine.fr",
        "host": "127.0.0.1",
        "port": "8080"
    }
}

TOKENS = {
    "Token MongoDB": {
        "token_id": "",
        "token_secret": ""
    },
    "Token SSH": {
        "token_id": "",
        "token_secret": ""
    }
}

class CloudflaredTab:
    def __init__(self, parent, cloudflared_path_var):
        self.frame = ttk.Frame(parent)
        self.cloudflared_path_var = cloudflared_path_var

        self.profile_var = tk.StringVar(value="Default")
        self.profile_menu = ttk.Combobox(self.frame, textvariable=self.profile_var, state="readonly")
        self.profile_menu['values'] = list(PRESETS.keys())
        self.profile_menu.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        self.profile_menu.bind("<<ComboboxSelected>>", self.load_profile)

        self.import_btn = ttk.Button(self.frame, text="Importer", command=self.import_config)
        self.import_btn.grid(row=0, column=1, padx=2 ,sticky='ew')

        self.save_btn = ttk.Button(self.frame, text="Enregistrer", command=self.save_config)
        self.save_btn.grid(row=0, column=2, padx=(0, 5),sticky='ew')

        ttk.Label(self.frame, text="Tokens :").grid(row=0, column=3, sticky="e")
        self.token_profile_var = tk.StringVar(value="")
        self.token_menu = ttk.Combobox(self.frame, textvariable=self.token_profile_var, state="readonly")
        self.token_menu['values'] = list(TOKENS.keys())
        self.token_menu.grid(row=0, column=4, sticky="ew", padx=5)
        self.token_menu.bind("<<ComboboxSelected>>", self.load_token_profile)

        ttk.Button(self.frame, text="Importer Token", command=self.import_tokens).grid(row=0, column=5, padx=5,sticky='w')

        ttk.Label(self.frame, text="Hostname :").grid(row=1, column=0, sticky="e")
        self.hostname_entry = ttk.Entry(self.frame)
        self.hostname_entry.grid(row=1, column=1, columnspan=5, sticky="ew", padx=5, pady=5)

        ttk.Label(self.frame, text="Hôte local :").grid(row=2, column=0, sticky="e")
        self.host_entry = ttk.Entry(self.frame)
        self.host_entry.grid(row=2, column=1, sticky="ew", padx=5, pady=5)

        ttk.Label(self.frame, text="Port :").grid(row=2, column=2, sticky="e")
        self.port_entry = ttk.Entry(self.frame, width=10)
        self.port_entry.grid(row=2, column=3, sticky="w", padx=5, pady=5)

        self.use_token_var = tk.BooleanVar()
        self.use_token_check = ttk.Checkbutton(self.frame, text="Utiliser un Service Token", variable=self.use_token_var, command=self.toggle_token_fields)
        self.use_token_check.grid(row=3, columnspan=6, sticky="w", padx=5)

        ttk.Label(self.frame, text="Token ID :").grid(row=4, column=0, sticky="e")
        self.token_id_entry = ttk.Entry(self.frame, state="disabled")
        self.token_id_entry.grid(row=4, column=1, columnspan=5, sticky="ew", padx=5, pady=5)

        ttk.Label(self.frame, text="Token Secret :").grid(row=5, column=0, sticky="e")
        self.token_secret_entry = ttk.Entry(self.frame, state="disabled")
        self.token_secret_entry.grid(row=5, column=1, columnspan=5, sticky="ew", padx=5, pady=5)

        self.launch_button = ttk.Button(self.frame, text="Lancer la connexion", command=self.run_cloudflared)
        self.launch_button.grid(row=6, columnspan=6, pady=10)

        for i in range(6):
            self.frame.columnconfigure(i, weight=1)

    def toggle_token_fields(self):
        state = "normal" if self.use_token_var.get() else "disabled"
        self.token_id_entry.configure(state=state)
        self.token_secret_entry.configure(state=state)

    def load_profile(self, event=None):
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
        name = self.token_profile_var.get()
        token = TOKENS.get(name, {})
        self.token_id_entry.delete(0, tk.END)
        self.token_id_entry.insert(0, token.get("token_id", ""))
        self.token_secret_entry.delete(0, tk.END)
        self.token_secret_entry.insert(0, token.get("token_secret", ""))

    def save_config(self):
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
        messagebox.showinfo("Sauvegarde", f"Configuration '{name}' enregistrée.")

    def import_config(self):
        if not os.path.exists(CONFIG_FILE):
            return
        with open(CONFIG_FILE, "r") as f:
            loaded = json.load(f)
            PRESETS.update(loaded)
            self.profile_menu['values'] = list(PRESETS.keys())
            messagebox.showinfo("Import", "Configurations importées.")

    def import_tokens(self):
        if not os.path.exists(TOKENS_FILE):
            return
        with open(TOKENS_FILE, "r") as f:
            loaded = json.load(f)
            TOKENS.update(loaded)
            self.token_menu['values'] = list(TOKENS.keys())
            messagebox.showinfo("Import", "Tokens importés.")

    def run_cloudflared(self):
        path = self.cloudflared_path_var.get()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Erreur", "Chemin vers cloudflared non valide.")
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
            subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_CONSOLE)
            messagebox.showinfo("Succès", f"Connexion vers {hostname} lancée.")
        except Exception as e:
            messagebox.showerror("Erreur", f"Échec d'exécution : {e}")

class CloudflaredGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Gestionnaire Cloudflared TCP Tunnel")
        self.cloudflared_path_var = tk.StringVar()
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

    def detect_cloudflared(self):
        path = shutil.which("cloudflared")
        if path:
            self.cloudflared_path_var.set(path)

    def browse_exe(self):
        path = filedialog.askopenfilename(title="Sélectionner cloudflared.exe", filetypes=[("Executable", "*.exe")])
        if path:
            self.cloudflared_path_var.set(path)

    def download_cloudflared(self):
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

    def open_download_page(self):
        webbrowser.open("https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/")

    def add_tab(self):
        self.tab_count += 1
        tab = CloudflaredTab(self.tab_control, self.cloudflared_path_var)
        self.tabs.append(tab)
        self.tab_control.add(tab.frame, text=f"Connexion {self.tab_count}")
        self.tab_control.select(len(self.tabs) - 1)

    def remove_current_tab(self):
        if len(self.tabs) <= 1:
            messagebox.showinfo("Impossible", "Impossible de supprimer le dernier onglet.")
            return
        current = self.tab_control.index(self.tab_control.select())
        self.tab_control.forget(current)
        del self.tabs[current]

if __name__ == "__main__":
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            PRESETS.update(json.load(f))
    if os.path.exists(TOKENS_FILE):
        with open(TOKENS_FILE, "r") as f:
            TOKENS.update(json.load(f))

    root = tk.Tk()
    app = CloudflaredGUI(root)
    root.mainloop()
