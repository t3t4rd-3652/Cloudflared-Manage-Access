import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import subprocess
import os
import webbrowser
import urllib.request
import json
import shutil
import paramiko
import atexit
import socket
import string
import sys
from pathlib import Path
import platform
import random
import threading
import select
from PIL import Image,ImageTk
import signal
import time
import re
import tempfile
import shlex

VERSION = "1.4.1"
#################################
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

# Définition du dossier APPDATA pour stocker les clés SSH du projet
def get_appdata_dir():
    system = platform.system()
    if system == "Windows":
        return os.path.join(os.getenv("APPDATA"), "CloudflaredManager")
    elif system == "Darwin":
        return os.path.join(Path.home(), "Library", "Application Support", "CloudflaredManager")
    else:
        return os.path.join(Path.home(), ".config", "CloudflaredManager")

def get_user_dir():
    system = platform.system()
    if system == "Windows":
        return os.path.join(os.getenv("USERPROFILE"))
    elif system == "Darwin":
        return os.path.join(Path.home(), "Library", "Application Support", "CloudflaredManager")
    else:
        return os.path.join(Path.home(), ".config", "CloudflaredManager")

################ - JSON - ######################

STARTUP_WARNINGS = []


def read_json(path):
    """Lit un fichier JSON en UTF-8, avec repli cp1252 pour les fichiers écrits par les anciennes versions."""
    last_error = None
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            with open(path, "r", encoding=encoding) as f:
                return json.load(f)
        except UnicodeDecodeError as e:
            last_error = e
    raise last_error


def write_json(path, data):
    """Écrit un fichier JSON en UTF-8 de façon atomique : fichier temporaire, puis remplacement."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def load_config_file(path):
    """
    Charge un fichier de configuration {nom: {...}}.
    Un fichier illisible est mis de côté en .bak au lieu d'empêcher le démarrage.
    """
    if not os.path.exists(path):
        return {}
    try:
        data = read_json(path)
        if not isinstance(data, dict) or not all(isinstance(v, dict) for v in data.values()):
            raise ValueError("structure inattendue")
        return data
    except Exception as e:
        backup = f"{path}.{time.strftime('%Y%m%d-%H%M%S')}.bak"
        try:
            os.replace(path, backup)
        except OSError:
            backup = path
        STARTUP_WARNINGS.append(
            f"{os.path.basename(path)} est illisible ({e}).\nIl a été mis de côté sous {os.path.basename(backup)}."
        )
        return {}


def load_import_file(file_path):
    """Lit un fichier importé et vérifie qu'il a la forme {nom: {...}}. Lève ValueError sinon."""
    data = read_json(file_path)
    if not isinstance(data, dict) or not all(isinstance(v, dict) for v in data.values()):
        raise ValueError("Le fichier doit contenir un objet JSON de la forme {\"nom\": {...}}.")
    return data

################ - VARIABLES - ######################

APPDATA_DIR = get_appdata_dir()
os.makedirs(APPDATA_DIR, exist_ok=True)
SSH_KEY_DIR = Path(APPDATA_DIR) / "ssh_keys"
SSH_KEY_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR = os.path.join(APPDATA_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

active_paramiko_connections = {}
# Chaque connexion cloudflared est un dict : proc, hostname, url, token_name, log_path.
cloudflared_processes = []
active_ssh_tunnels = []
ssh_keys_summary = []

CONFIG_FILE = os.path.join(APPDATA_DIR, "cloudflared_configs.json")
TOKENS_FILE = os.path.join(APPDATA_DIR, "cloudflared_tokens.json")
SSH_REDIR_FILE = os.path.join(APPDATA_DIR, "cloudflared_ssh_redir.json")


def prune_old_logs(max_age_days=7):
    """Supprime les journaux cloudflared de plus de max_age_days jours."""
    limit = time.time() - max_age_days * 86400
    for name in os.listdir(LOG_DIR):
        full = os.path.join(LOG_DIR, name)
        try:
            if name.startswith("cloudflared-") and os.path.getmtime(full) < limit:
                os.remove(full)
        except OSError:
            pass


prune_old_logs()

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
if os.path.isfile(SSH_REDIR_FILE):
    SSH_REDIR = {}
else:
    SSH_REDIR = {
    "Default": {
        "host": "localhost",
        "port": "22",
        "user": ""
    }
}

## - IMAGE - ##
dir_ico = resource_path("ico") #DOSSIER IMAGE


def load_icon(name, size=15):
    return Image.open(os.path.join(dir_ico, name)).resize((size, size))


add_ico = load_icon("add.png")
delete_ico = load_icon("delete.png")
edit_ico = load_icon("edit.png")
export_ico = load_icon("export.png")
import_ico = load_icon("import.png")
save_ico = load_icon("save.png")
project_ico = os.path.join(dir_ico, "cloudflared.ico")


def set_window_icon(window):
    """Applique l'icône du projet ; iconbitmap(.ico) n'existe que sous Windows."""
    try:
        if platform.system() == "Windows":
            window.iconbitmap(project_ico)
        else:
            window.iconphoto(False, ImageTk.PhotoImage(Image.open(project_ico)))
    except Exception:
        pass

################################################

def load_existing_ssh_keys():
    if SSH_KEY_DIR.exists():
        for k in SSH_KEY_DIR.glob("*"):
            if (
                k.is_file()
                and not k.name.endswith(".pub")
                and os.access(k, os.R_OK)
                and not k.name.startswith("known_hosts")):
                if str(k) not in ssh_keys_summary:
                    ssh_keys_summary.append(str(k))

load_existing_ssh_keys()

def cleanup_ssh_tunnels():
    # Tunnels lancés via clé privée
    for label, proc in [t for t in active_ssh_tunnels if len(t) == 2]:
        try:
            proc.terminate()
        except Exception as e:
            print("ERROR CLEANUP KEY:", e)

    # Tunnels lancés via mot de passe
    for label, client, stop_event in [t for t in active_ssh_tunnels if len(t) == 3]:
        try:
            if isinstance(stop_event, threading.Event):
                stop_event.set()
            client.close()
        except Exception as e:
            print("ERROR CLEANUP PASSWORD:", e)

def timed_messagebox(title, message, duration=8000):
    def on_closing(parent):
        parent.destroy()

    top = tk.Toplevel()
    set_window_icon(top)
    top.title(title)
    top.geometry("400x100")
    top.protocol("WM_DELETE_WINDOW", lambda parent=top:on_closing(parent))
    top.resizable(False, False)
    tk.Label(top, text=message, wraplength=380, justify="left").pack(padx=10, pady=10)
    top.after(duration, lambda parent=top: on_closing(parent))

    top.attributes('-topmost', True)
    top.grab_set()


def prune_dead_connections():
    """Retire de la liste les cloudflared qui se sont arrêtés d'eux-mêmes."""
    for entry in list(cloudflared_processes):
        if entry["proc"].poll() is not None:
            cloudflared_processes.remove(entry)


def update_connection_status():
    prune_dead_connections()
    status_text = (f"Connexions ouvertes : {len(cloudflared_processes)} Cloudflare · "
                   f"{len(active_ssh_tunnels)} SSH  (cliquer pour fermer)")
    gui = globals().get("app")
    if gui is not None and hasattr(gui, 'status_label'):
        gui.status_label.config(text=status_text)


def terminate_process(proc, timeout=3):
    """Arrête un processus lancé directement (plus de PowerShell intermédiaire, donc pas d'arbre à tuer)."""
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
            proc.wait(timeout=timeout)
        except Exception:
            pass
    except Exception:
        pass


def describe_connection(entry):
    token = f" | Token : {entry['token_name']}" if entry.get("token_name") else ""
    return f"{entry['hostname']} → {entry['url']}{token}"


def close_cloudflared_connection(entry):
    if entry in cloudflared_processes:
        cloudflared_processes.remove(entry)
    terminate_process(entry["proc"])
    update_connection_status()
    timed_messagebox("Connexion fermée", f"Connexion {entry['hostname']} arrêtée.")


def show_close_dialog():
    """Boîte de sélection de la connexion cloudflared à fermer."""
    prune_dead_connections()
    if not cloudflared_processes:
        timed_messagebox("Erreur", "Aucune connexion active à fermer.")
        return
    dialog = tk.Toplevel()
    set_window_icon(dialog)
    dialog.title("Fermer une connexion")
    dialog.geometry("460x280")
    dialog.resizable(False, False)
    ttk.Label(dialog, text="Sélectionnez une connexion à fermer :").pack(pady=10)
    listbox = tk.Listbox(dialog, width=80)
    listbox.pack(padx=10, pady=5, fill="both", expand=True)
    entries = list(cloudflared_processes)
    for entry in entries:
        listbox.insert(tk.END, describe_connection(entry))

    def on_select():
        selected = listbox.curselection()
        if selected:
            dialog.destroy()
            close_cloudflared_connection(entries[selected[0]])

    ttk.Button(dialog, text="Fermer la connexion sélectionnée", command=on_select).pack(pady=10)
    dialog.attributes('-topmost', True)
    dialog.grab_set()


def cleanup():
    # Arrête proprement les cloudflared encore actifs
    for entry in list(cloudflared_processes):
        try:
            terminate_process(entry["proc"])
        except Exception as e:
            print("cleanup error:", e)

atexit.register(cleanup_ssh_tunnels)
##

class SSHRedirector:
    def __init__(self, parent):
        self.top = tk.Toplevel(parent)
        # - IMG
        self.add_tk = ImageTk.PhotoImage(add_ico,(10,10))
        self.save_tk = ImageTk.PhotoImage(save_ico,(10,10))
        self.delete_ico = ImageTk.PhotoImage(delete_ico,(10,10))
        self.edit_ico = ImageTk.PhotoImage(edit_ico,(10,10))
        self.export_ico = ImageTk.PhotoImage(export_ico,(10,10))
        self.import_ico = ImageTk.PhotoImage(import_ico,(10,10))
        # - FENETRE ROOT
        set_window_icon(self.top)
        self.top.title("Redirection SSH")
        self.top.geometry("420x660")
        self.top.protocol("WM_DELETE_WINDOW", self.on_close)
        self.top.resizable(False, False)
        # Configuration du grid global
        self.top.columnconfigure(0, weight=1)
        self.top.columnconfigure(1, weight=1)
        # Ligne 0 - Profil de connexions
        # RAJOUTER UNE COMBOBOX AFIN DE PRENDRE EN COMPTE DES PROFILS DE CONNEXIONS DE REDIRECTION SSH 
        self.profile_redirect_var = tk.StringVar(value="Default")
        self.profile_redirect = ttk.Combobox(self.top, textvariable=self.profile_redirect_var, state="readonly")
        self.profile_redirect.bind("<<ComboboxSelected>>", self.load_profile_ssh)
        self.load_configs_ssh()
        frame_ico = ttk.Frame(self.top)
        # - BUTTON
        add_button = ttk.Button(frame_ico, image=self.add_tk, command=self.add_config_ssh)
        save_button = ttk.Button(frame_ico, image=self.save_tk, command=self.save_config_ssh)
        delete_button = ttk.Button(frame_ico, image=self.delete_ico, command=self.delete_profile_ssh)
        edit_button = ttk.Button(frame_ico, image=self.edit_ico, command=self.rename_profile_ssh)
        import_button = ttk.Button(frame_ico, image=self.import_ico, command=self.import_profile_ssh)
        export_button = ttk.Button(frame_ico, image=self.export_ico, command=self.export_profile_ssh)
        # Ligne 1 - Hôte distant
        label_host = ttk.Label(self.top, text="Hôte (IP ou nom) :")
        self.host_entry_ssh = ttk.Entry(self.top)
        # Ligne 2 - Port SSH distant
        label_port = ttk.Label(self.top, text="Port (défaut : 22) :")
        self.port_entry_ssh = ttk.Entry(self.top, width=8)
        self.port_entry_ssh.insert(0, "22")
        # Ligne 3 - Nom utilisateur SSH
        label_ssh_user = ttk.Label(self.top, text="Utilisateur SSH :")
        self.user_entry_ssh = ttk.Entry(self.top)
        # Ligne 4 - Frame pour checkbox + bouton
        self.var_check = tk.IntVar(value=1)
        self.check_button = ttk.Checkbutton(self.top, text='Connexion avec Mot de passe',variable=self.var_check, onvalue=1, offvalue=0)
        button_list_port = ttk.Button(self.top, text="Lister les ports ouverts", command=self.list_ports)#.pack(side="left", padx=(10, 0),fill='x',expand=True)
        # Ligne 5 - Liste ports ouverts
        self.ports_listbox = tk.Listbox(self.top, height=6)
        tooltip = Tooltip(self.ports_listbox)
        self.ports_listbox.bind("<Enter>", lambda e: tooltip.show_tooltip(e.x_root, e.y_root))
        self.ports_listbox.bind("<Motion>", lambda e: (self.on_motion(tooltip, self.ports_listbox, e)))
        self.ports_listbox.bind("<Leave>",  lambda e: self.on_leave(tooltip, e))
        # Ligne 6 - Port local
        check_frame_port = ttk.Frame(self.top)
        label_port_wanted = ttk.Label(check_frame_port, text="Port local souhaité :")#.grid(row=9, column=0, pady=5, sticky="w", padx=10)
        self.local_port_entry = ttk.Entry(check_frame_port, width=8)
        # Ligne 7 - Bouton créer tunnel
        self.run_btn = ttk.Button(self.top, text="Créer le tunnel SSH", command=self.create_ssh_tunnel)
        # Ligne 8 - Séparateur
        separator_1 = ttk.Separator(self.top)
        # Ligne 9 - Connexions ouvertes
        label_port_open = ttk.Label(self.top, text="Tunnels SSH ouverts :")
        self.conn_listbox = tk.Listbox(self.top, height=6)
        # Ligne 10 - Gestion des connexions
        open_selected_line = ttk.Button(self.top,text="Ouvrir la page sélectionnée",command=self.open_redir_web) ##LAST ADD 
        close_selected_line = ttk.Button(self.top, text="Fermer la connexion sélectionnée", command=self.close_selected_connection)
        # Ligne 11 - Séparateur
        separator_2 = ttk.Separator(self.top)
        # Ligne 12 - Clés SSH générées
        label_generated_ssh_key = ttk.Label(self.top, text="Clés SSH générées :")
        # Ligne 13 - Listbox des clés générées
        self.keys_listbox = tk.Listbox(self.top, height=4)
        # Ligne 14 - Frame actions clés
        self.key_actions_frame = ttk.Frame(self.top)
        delete_selected_key = ttk.Button(self.key_actions_frame, text="Supprimer la clé sélectionnée", command=self.delete_selected_key)
        send_selected_key = ttk.Button(self.key_actions_frame, text="Envoyer la clé sélectionnée", command=self.send_selected_key)
        # - FUNCTION - INIT - #
        self.refresh_connection_list()
        self.refresh_key_list()
        if self.profile_redirect_var.get() in SSH_REDIR:
            self.load_profile_ssh()
        ########### - GRID - #############
        #ROW 0
        self.profile_redirect.grid(row=0, column=0, sticky="ew", padx=(10,5), pady=(7,2),columnspan=2)
        frame_ico.grid(row=0, column=2, sticky="ew", padx=(5,0), pady=(5,2),columnspan=4)
        add_button.grid(row=0, column=0, sticky="w", padx=(0,5), pady=(5,2),columnspan=1)
        save_button.grid(row=0, column=1, sticky="w", padx=5, pady=(5,2),columnspan=1)
        edit_button.grid(row=0, column=2, sticky="w", padx=5, pady=(5,2),columnspan=1)
        import_button.grid(row=0, column=3, sticky="w", padx=5, pady=(5,2),columnspan=1)
        export_button.grid(row=0, column=4, sticky="w", padx=5, pady=(5,2),columnspan=1)
        delete_button.grid(row=0, column=5, sticky="w", padx=(5,10), pady=(5,2),columnspan=2)
        # 1
        label_host.grid(row=1, column=0, pady=5, sticky="w", padx=(10,0),columnspan=2)
        self.host_entry_ssh.grid(row=1, column=1, padx=(0,10), sticky="ew", columnspan=5)
        # 2 
        label_port.grid(row=2, column=0, pady=5, sticky="w", padx=(10,0))
        self.port_entry_ssh.grid(row=2, column=1, padx=(0,10), sticky="w",columnspan=2)
        # 3
        label_ssh_user.grid(row=3, column=0, pady=5, sticky="w", padx=(10,0))
        self.user_entry_ssh.grid(row=3, column=1, padx=(0,10), sticky="ew", columnspan=5)
        # 4 
        self.check_button.grid(row=4, column=0, columnspan=4, sticky="ew", padx=10, pady=5)
        button_list_port.grid(row=4, column=3, columnspan=2, sticky="ew", padx=10, pady=5)
        # 5
        self.ports_listbox.grid(row=5, column=0, padx=10, pady=5, sticky="nsew", columnspan=6)
        # 6 
        check_frame_port.grid(row=6, column=0, columnspan=2, sticky="ew", padx=10)
        label_port_wanted.pack(side="left")
        self.local_port_entry.pack(side="left", padx=(10, 0))#.grid(row=9, column=1, sticky="w", padx=(0,10))
        self.run_btn.grid(row=6, column=3, columnspan=2, pady=0, padx=(10,10), sticky="ew")
        # 7 
        separator_1.grid(row=7, column=0, columnspan=6, sticky="ew", pady=10)
        # 8
        label_port_open.grid(row=8, column=0, pady=0, sticky="ew",padx=10)
        # 9
        self.conn_listbox.grid(row=9, column=0, padx=10, sticky="nsew", columnspan=6)
        # 10 
        open_selected_line.grid(row=10, column=0, pady=10,padx=(25,5), sticky="ew",columnspan=2)
        close_selected_line.grid(row=10, column=3, pady=10,padx=(5,25), sticky="ew",columnspan=2)
        # 11
        separator_2.grid(row=11, column=0, sticky="ew", pady=10, columnspan=6)
        # 12
        label_generated_ssh_key.grid(row=12, column=0, pady=0, sticky="w", columnspan=2,padx=10)
        # 13
        self.keys_listbox.grid(row=13, column=0, padx=10, sticky="nsew", columnspan=6)
        # 14
        self.key_actions_frame.grid(row=14, column=0, pady=5, columnspan=5)
        delete_selected_key.grid(row=0, column=0, padx=5,columnspan=2)
        send_selected_key.grid(row=0, column=3, padx=5, columnspan=2)
        ####################################

    def init_connection(self,host,port,user):
        conn_key = (host,port,user)
        if conn_key in active_paramiko_connections:
            password,transport,client = active_paramiko_connections[conn_key]
            # print(f"[INFO] Réutilisation connexion: {host}:{port} ({user})")
            if transport.is_active():
                pass
            else:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(hostname=host,
                port=port,
                username=user,
                password=password,
                look_for_keys=False,
                allow_agent=False)
                transport = client.get_transport()
                active_paramiko_connections[conn_key] = (password,transport,client)
        else:
            password = simpledialog.askstring("Mot de passe SSH", f"Mot de passe pour {user}@{host}:{port}", show='*')
            if password != None:
                password = password.strip()
                if password == '':
                    messagebox.showwarning("Annulé", "Mot de passe non fourni.")
                    return self.init_connection(host,port,user)
            else:
                messagebox.showwarning("Annulé", "L'utilisateur a annulé la saisie")
                return
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host,
            port=port,
            username=user,
            password=password,
            look_for_keys=False,
            allow_agent=False)
            transport = client.get_transport()
            active_paramiko_connections[conn_key] = (password,transport,client)
        return client

    def read_ssh_port(self):
        value = self.port_entry_ssh.get().strip() or "22"
        if not value.isdigit() or not 0 < int(value) < 65536:
            messagebox.showerror("Port invalide", "Le port SSH doit être un nombre entre 1 et 65535.")
            return None
        return int(value)

    def on_motion(self, tooltip, listbox, event):
        idx = listbox.nearest(event.y)
        if 0 <= idx < listbox.size():
            # value = listbox.get(idx)
            tooltip.set_text(f"{self.ports_info[idx][-1]}")
            # Créer la fenêtre si besoin
            if tooltip.tooltip_window is None:
                tooltip.show_tooltip(event.x_root, event.y_root)
            else:
                # La faire suivre le curseur
                tooltip.follow_mouse(event)

    def on_leave(self, tooltip, event):
        tooltip.hide_tooltip()

    def on_close(self):
        cleanup_ssh_tunnels()
        self.top.destroy()

    def refresh_key_list(self):
        self.keys_listbox.delete(0, tk.END)
        for path in ssh_keys_summary:
            self.keys_listbox.insert(tk.END, path)

    def generate_random_key_name(self):
        return "id_ed25519_" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))

    def generate_ssh_key(self):
        custom_name_ = simpledialog.askstring("Nom de la clé", "Nom personnalisé pour la clé (laisser vide pour auto)")
        if not custom_name_:
            custom_name = self.generate_random_key_name()
        else:
            custom_name = "id_ed25519_" + custom_name_
        key_path = SSH_KEY_DIR / custom_name
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(key_path), "-N", ""])
        ssh_keys_summary.append(str(key_path))
        self.refresh_key_list()
        return custom_name

    def send_ssh_key_to_server(self, host, port, username, key_name):
        pubkey_path = SSH_KEY_DIR / f"{key_name}.pub"
        with open(pubkey_path, "r") as f:
            pubkey = f.read().strip()

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        password = simpledialog.askstring("Mot de passe SSH", f"Mot de passe pour {username}@{host}:{port}", show='*')
        if password is None:
            return
        # Une seule commande, exécutée jusqu'au bout : crée ~/.ssh si besoin et n'ajoute la clé que si elle manque.
        quoted = shlex.quote(pubkey)
        command = (
            "umask 077 && mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys"
            " && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys"
            f" && (grep -qxF {quoted} ~/.ssh/authorized_keys || printf '%s\\n' {quoted} >> ~/.ssh/authorized_keys)"
        )
        try:
            ssh.connect(hostname=host, port=port, username=username, password=password)
            _, stdout, stderr = ssh.exec_command(command)
            status = stdout.channel.recv_exit_status()
            error_text = stderr.read().decode("utf-8", "replace").strip()
            ssh.close()
            if status != 0:
                raise RuntimeError(error_text or f"code de retour {status}")
            messagebox.showinfo("Succès", "Clé SSH copiée avec succès.")
        except Exception as e:
            messagebox.showerror("Erreur SSH", str(e))

    def send_selected_key(self):
        selected = self.keys_listbox.curselection()
        if not selected:
            return
        key_path = Path(self.keys_listbox.get(selected[0]))
        key_name = key_path.name
        host = self.host_entry_ssh.get().strip()
        port = self.read_ssh_port()
        if port is None:
            return
        user = self.user_entry_ssh.get().strip()
        self.send_ssh_key_to_server(host, port, user, key_name)

    def delete_selected_key(self):
        selected = self.keys_listbox.curselection()
        if not selected:
            return
        key_path = Path(self.keys_listbox.get(selected[0]))
        confirm = messagebox.askyesno("Supprimer", f"Supprimer la clé {key_path.name} ?")
        if confirm:
            try:
                key_path.unlink(missing_ok=True)
                pub_path = key_path.with_suffix(".pub")
                pub_path.unlink(missing_ok=True)
                ssh_keys_summary.remove(str(key_path))
                self.refresh_key_list()
            except Exception as e:
                messagebox.showerror("Erreur", str(e))

    def list_ports(self):
        host = self.host_entry_ssh.get().strip()
        port = self.read_ssh_port()
        if port is None:
            return
        user = self.user_entry_ssh.get().strip()
        try:
            if self.var_check.get() == 0:
                key_files = list(SSH_KEY_DIR.glob("id_ed25519*"))
                key_file = next((k for k in key_files if k.name.endswith(".pub") is False), None)
                if not key_file:
                    confirm = messagebox.askyesno(
                        "Clé SSH manquante",
                        "Aucune clé SSH détectée. Voulez-vous en générer une et l'envoyer maintenant ?"
                    )
                    if confirm:
                        key_name = self.generate_ssh_key()
                        self.send_ssh_key_to_server(host, port, user, key_name)
                        messagebox.showinfo("Info", "Clé créée et envoyée. Vous pouvez relancer la récupération des ports.")
                    return

                pkey = paramiko.Ed25519Key(filename=str(key_file))
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(hostname=host, port=port, username=user, pkey=pkey)
            else:
                client = self.init_connection(host, port, user)

            if client:
                stdin, stdout, stderr = client.exec_command("ports-report")
                output = stdout.readlines()
                if stdout.channel.recv_exit_status() == 127:
                    messagebox.showwarning(
                        "ports-report absent",
                        "Le script ports-report n'est pas installé sur le serveur.\n"
                        "Installez-le avec server/install.sh (voir docs/SERVEUR.md).")
                    return
                self.ports_listbox.delete(0, tk.END)
                self.ports_info = []
                try:
                    for line in output:
                        parts = line.split()
                        if parts:
                            protocol = parts[0]
                            port_ssh = parts[1]
                            service = parts[2]
                            # print(parts)
                            match len(parts):
                                case 5:
                                    code_name = parts[3];code_int = parts[4]
                                    total_code = code_name + " " + code_int
                                    match code_int:
                                        case '200':
                                            if parts[2] == '-':
                                                service = 'WebApp'
                                            final_code = code_name + f' ✅'
                                        case '-':
                                            final_code = ' ❓'; total_code = "Protocol non HTTP"
                                        case "302":
                                            final_code = code_name + ' ❓'
                                        case "301":
                                            final_code = code_name + ' ❓'
                                        case '400':
                                            if parts[2] == '-':
                                                service = 'WebApp'
                                            final_code = code_name + ' ❌'
                                        case _:
                                            if parts[2] == '-':
                                                service = 'WebApp'
                                            final_code = code_name + f' ❌'
                                case 4:
                                    # "tcp PORT NOM -" : service sans réponse HTTP
                                    total_code = "Protocole non HTTP"
                                    final_code = " ❓"
                                case 6:
                                    if service == 'http-alt':
                                        service = 'WebApp'
                                    code_name = parts[-2];code_int = parts[-1]
                                    total_code = code_name + " " + code_int
                                    final_code = code_name + ' ✅' if code_int == "200" else code_name + " ❌" if code_int == '404' else code_name + ' ❓'
                                case _:
                                    total_code = "Protocol non HTTP"
                                    final_code = f'❓'
                            self.ports_info.append((protocol,port_ssh,service,final_code,total_code))

                    # Insertion dans la Listbox
                    for protocol, port_ssh, service, final_code,total_code in self.ports_info:
                        self.ports_listbox.insert(tk.END, f"{protocol} ({port_ssh}) - {service} → {final_code}")
                        # Tooltip(key,f'Dernière Maj:\n{bdd_getime()}',font=('Roboto',12,'bold'))
                except Exception as e:
                    print(e)
                    return
            else:
                return
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de récupérer les ports : {e}")
            
    def create_ssh_tunnel(self):
        def is_port_in_use(port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                return s.connect_ex(('localhost', port)) == 0
        host = self.host_entry_ssh.get().strip()
        port = self.read_ssh_port()
        if port is None:
            return
        user = self.user_entry_ssh.get().strip()
        selected = self.ports_listbox.curselection()
        if not selected:
            messagebox.showwarning("Aucun port sélectionné", "Veuillez sélectionner un port distant à rediriger.")
            return
        selected_text = self.ports_listbox.get(selected[0])
        protocol_base = selected_text.split(" ")[-2]
        protocol = 'http://' if protocol_base == 'HTTP' else 'https://' if protocol_base == 'HTTPS' else ""
        remote_port = selected_text.split()[1].strip("()")
        local_port = self.local_port_entry.get().strip()
        if not local_port.isdigit():
            messagebox.showerror("Erreur", "Le port local doit être un nombre entier.")
            return
        local_port = int(local_port)

        if is_port_in_use(local_port):
            messagebox.showerror("Port occupé", f"Le port local {local_port} est déjà utilisé.")
            return
        
        if self.var_check.get() == 0:
                key_files = list(SSH_KEY_DIR.glob("id_ed25519*"))
                key_file = next((k for k in key_files if k.name.endswith(".pub") is False), None)
                if not key_file:
                    confirm = messagebox.askyesno("Clé SSH manquante", "Aucune clé SSH détectée. Voulez-vous en générer une et l'envoyer maintenant ?")
                    if confirm:
                        key_name = self.generate_ssh_key()
                        self.send_ssh_key_to_server(host, port, user, key_name)
                        messagebox.showinfo("Info", "Clé créée et envoyée. Vous pouvez relancer la récupération des ports.")
                    return
                
                cmd = ["ssh", "-i", str(key_file), "-p", str(port), "-N",
                        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
                        "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=30",
                        "-L", f"{local_port}:localhost:{remote_port}", f"{user}@{host}"]
                try:
                    kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW} if platform.system() == "Windows" else {}
                    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, **kwargs)
                    active_ssh_tunnels.append((f"{protocol}{user}:{remote_port} → {protocol}localhost:{local_port} {user}@{host}:{port}", proc))
                    self.refresh_connection_list()
                    # print(cmd)
                    messagebox.showinfo("Tunnel actif", f"""L'adresse localhost:{local_port} redirige le port {remote_port}\nde la connexion {user}@{host}:{port}""")
                except Exception as e:
                    messagebox.showerror("Erreur de tunnel", str(e))


        else:
            try:
                client = self.init_connection(host, port, user)
            except Exception as e:
                messagebox.showerror("Connexion SSH impossible", str(e))
                return
            if client is None:
                return
            transport = client.get_transport()

            def handler(chan, sock):
                try : 
                    while True:
                        r, w, x = select.select([sock, chan], [], [])
                        if sock in r:
                            data = sock.recv(1024)
                            if not data:
                                break
                            chan.send(data)
                        if chan in r:
                            data = chan.recv(1024)
                            if not data:
                                break
                            sock.send(data)
                except Exception as e:
                    print('Handler Error: ', e)
                chan.close()
                sock.close()

            def forward_tunnel(local_port, remote_host, remote_port, transport, stop_event):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.bind(('127.0.0.1', local_port))
                    sock.listen(100)
                    # print(f"[Tunnel] Écoute sur 127.0.0.1:{local_port} vers {remote_host}:{remote_port} (distant)")
                    while not stop_event.is_set():
                        try:
                            sock.settimeout(1)  # permet de vérifier stop_event régulièrement
                            client_sock, addr = sock.accept()
                        except socket.timeout:
                            continue
                        # print(f"[Tunnel] Connexion reçue depuis {addr}")
                        try:
                            chan = transport.open_channel(
                                "direct-tcpip",
                                (remote_host, remote_port),
                                ('127.0.0.1', 0)
                            )
                        except Exception as e:
                            print(f"[Tunnel] Erreur open_channel: {e}")
                            client_sock.close()
                            continue
                        threading.Thread(target=handler, args=(chan, client_sock), daemon=True).start()
                    sock.close()
                except Exception as e:
                    print('Forward tunnel Error: ', e)

            import threading
            stop_event = threading.Event()
            t = threading.Thread(
                target=forward_tunnel,
                args=(local_port, "localhost", int(remote_port), transport,stop_event),
                daemon=True)
            t.start()

            active_ssh_tunnels.append((f"{protocol}{user}:{remote_port} → {protocol}localhost:{local_port} {user}@{host}:{port}", client,stop_event))
            # print(active_ssh_tunnels)
            self.refresh_connection_list()
            messagebox.showinfo("Tunnel actif", f"""L'adresse localhost:{local_port} redirige le port {remote_port}\nde la connexion {user}@{host}:{port}""")

    def refresh_connection_list(self):
        self.conn_listbox.delete(0, tk.END)
        for el in active_ssh_tunnels:
            label = el[0] if el else "Inconnu"
            self.conn_listbox.insert(tk.END, label)
            # self.conn_listbox.insert(tk.END, label)

    def close_selected_connection(self):
        selected = self.conn_listbox.curselection()
        if not selected:
            return
        index = selected[0]
        conn_data = active_ssh_tunnels.pop(index)

        if len(conn_data) == 2:
            # Connexion via clé privée (proc subprocess)
            label, proc = conn_data
            proc.terminate()
        elif len(conn_data) == 3:
            # Connexion via mot de passe (thread paramiko)
            label, client, stop_event = conn_data
            if isinstance(stop_event, threading.Event):
                stop_event.set()

        self.refresh_connection_list()
        messagebox.showinfo("Connexion fermée", f"Connexion {label} arrêtée.")

    def open_redir_web(self):
        selected = self.conn_listbox.curselection()
        if not selected:
            return
        label = active_ssh_tunnels[selected[0]][0]
        scheme_match = re.match(r"^(https?)://", label)
        scheme = scheme_match.group(1) if scheme_match else "http"
        port_match = re.search(r"localhost:(\d+)", label)
        if not port_match:
            messagebox.showerror("Erreur", "Impossible de déterminer le port local de ce tunnel.")
            return
        url = f"{scheme}://localhost:{port_match.group(1)}"
        try:
            webbrowser.open(url)
        except Exception as e:
            messagebox.showerror("Erreur", f"La page web n'a pas pu être ouverte : {e}")

    def load_configs_ssh(self):
        """Charge les profils de redirection SSH et met à jour la liste déroulante."""
        global SSH_REDIR
        SSH_REDIR.update(load_config_file(SSH_REDIR_FILE))
        self.profile_redirect['values'] = list(SSH_REDIR.keys())

    def load_profile_ssh(self, event=None):
        name = self.profile_redirect_var.get()
        config = SSH_REDIR.get(name, {})
        self.host_entry_ssh.delete(0, tk.END)
        self.host_entry_ssh.insert(0, config.get("host", "localhost"))
        self.port_entry_ssh.delete(0, tk.END)
        self.port_entry_ssh.insert(0, config.get("port", "22"))
        self.user_entry_ssh.delete(0, tk.END)
        self.user_entry_ssh.insert(0, config.get("user", ""))

    def save_ssh_profiles(self):
        write_json(SSH_REDIR_FILE, SSH_REDIR)
        self.profile_redirect['values'] = list(SSH_REDIR.keys())

    def save_config_ssh(self):
        """Sauvegarde le profil SSH courant dans le fichier JSON."""
        name = self.profile_redirect_var.get()
        if not name:
            return
        SSH_REDIR[name] = {
            "host": self.host_entry_ssh.get().strip(),
            "port": self.port_entry_ssh.get().strip(),
            "user": self.user_entry_ssh.get().strip(),
        }
        self.save_ssh_profiles()
        timed_messagebox("Sauvegarde", f"Profil SSH '{name}' enregistré.")

    def add_config_ssh(self):
        name = simpledialog.askstring("Nouveau profil SSH", "Nom du nouveau profil SSH :")
        if name and name not in SSH_REDIR:
            SSH_REDIR[name] = {}
            self.profile_redirect['values'] = list(SSH_REDIR.keys())
            self.profile_redirect_var.set(name)

    def delete_profile_ssh(self):
        name = self.profile_redirect_var.get()
        if name not in SSH_REDIR:
            return
        if messagebox.askyesno("Supprimer", f"Supprimer le profil SSH '{name}' ?"):
            del SSH_REDIR[name]
            self.profile_redirect_var.set('')
            self.save_ssh_profiles()

    def rename_profile_ssh(self):
        name = self.profile_redirect_var.get()
        if name not in SSH_REDIR:
            return
        new_name = simpledialog.askstring("Renommer le profil SSH", "Nouveau nom :", initialvalue=name)
        if new_name and new_name != name:
            SSH_REDIR[new_name] = SSH_REDIR.pop(name)
            self.profile_redirect_var.set(new_name)
            self.save_ssh_profiles()

    def import_profile_ssh(self):
        """Importe un fichier JSON de profils SSH et l'ajoute aux profils locaux."""
        file_path = filedialog.askopenfilename(title="Importer des profils SSH", filetypes=[("Fichiers JSON", "*.json")])
        if not file_path:
            return
        try:
            loaded = load_import_file(file_path)
        except Exception as e:
            messagebox.showerror("Import impossible", str(e))
            return
        SSH_REDIR.update(loaded)
        self.save_ssh_profiles()
        messagebox.showinfo("Import", f"Profils SSH importés : {', '.join(loaded.keys())}")

    def export_profile_ssh(self):
        """Exporte les profils SSH vers un fichier JSON choisi par l'utilisateur."""
        if not SSH_REDIR:
            messagebox.showwarning("Export", "Aucun profil SSH à exporter.")
            return
        file_path = filedialog.asksaveasfilename(
            title="Exporter les profils SSH",
            defaultextension=".json",
            initialfile="cloudflared_ssh_redir.json",
            filetypes=[("Fichiers JSON", "*.json")]
        )
        if not file_path:
            return
        try:
            write_json(file_path, SSH_REDIR)
            timed_messagebox("Export", f"Profils SSH exportés vers :\n{file_path}")
        except Exception as e:
            messagebox.showerror("Erreur d'export", f"Impossible d'exporter les profils SSH :\n{e}")




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
            write_json(CONFIG_FILE, PRESETS)

    def delete_profile(self):
        name = self.profile_var.get()
        if name not in PRESETS:
            return
        confirm = messagebox.askyesno("Supprimer", f"Supprimer le profil '{name}' ?")
        if confirm:
            del PRESETS[name]
            self.profile_menu['values'] = list(PRESETS.keys())
            self.profile_var.set('')
            write_json(CONFIG_FILE, PRESETS)

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
            write_json(TOKENS_FILE, TOKENS)

    def delete_token(self):
        name = self.token_profile_var.get()
        if name not in TOKENS:
            return
        confirm = messagebox.askyesno("Supprimer", f"Supprimer le token '{name}' ?")
        if confirm:
            del TOKENS[name]
            self.token_menu['values'] = list(TOKENS.keys())
            self.token_profile_var.set('')
            write_json(TOKENS_FILE, TOKENS)
                
    def __init__(self, parent, cloudflared_path_var):
        self.frame = ttk.Frame(parent)
        self.cloudflared_path_var = cloudflared_path_var
        self.add_ico = ImageTk.PhotoImage(add_ico,(10,10))
        self.save_ico = ImageTk.PhotoImage(save_ico,(10,10))
        self.delete_ico = ImageTk.PhotoImage(delete_ico,(10,10))
        self.edit_ico = ImageTk.PhotoImage(edit_ico,(10,10))
        self.export_ico = ImageTk.PhotoImage(export_ico,(10,10))
        self.import_ico = ImageTk.PhotoImage(import_ico,(10,10))
        # LIGNE 0 
        # PART PROFILE ##########RAJOUTER EXPORT
        self.profile_frame = ttk.Frame(self.frame)
        self.profile_var = tk.StringVar(value="Default")
        self.profile_menu = ttk.Combobox(self.profile_frame, textvariable=self.profile_var, state="readonly")
        self.profile_menu.bind("<<ComboboxSelected>>", self.load_profile)
        self.import_btn = ttk.Button(self.profile_frame, text="", image=self.import_ico, command=self.import_config)
        self.save_btn = ttk.Button(self.profile_frame, text="", image=self.save_ico, command=self.save_config)
        self.new_profile_btn = ttk.Button(self.profile_frame, text="", image=self.add_ico, width=3, command=self.create_new_profile)
        self.rename_profile_btn = ttk.Button(self.profile_frame, text="", image=self.edit_ico, width=3, command=self.rename_profile)
        self.delete_profile_btn = ttk.Button(self.profile_frame, text="", image=self.delete_ico, width=3, command=self.delete_profile)
        self.export_profile_btn = ttk.Button(self.profile_frame, image=self.export_ico, width=3, command=self.export_profile)
        #- PART TOKEN ########## - RAJOUTER EXPORT
        self.tokens_frame = ttk.Frame(self.frame)
        tokens_label = ttk.Label(self.tokens_frame, text="Tokens :")
        self.token_profile_var = tk.StringVar(value="")
        self.token_menu = ttk.Combobox(self.tokens_frame, textvariable=self.token_profile_var, state="readonly")
        self.token_menu.bind("<<ComboboxSelected>>", self.load_token_profile)
        self.import_tokens_button = ttk.Button(self.tokens_frame, text="", image=self.import_ico, command=self.import_tokens)
        self.save_tokens_button = ttk.Button(self.tokens_frame, text="", image=self.save_ico, command=self.save_token)
        self.add_tokens_button = ttk.Button(self.tokens_frame, text="", image=self.add_ico, width=3, command=self.create_new_token_profile)
        self.rename_token_btn = ttk.Button(self.tokens_frame, text="", image=self.edit_ico, width=3, command=self.rename_token)
        self.delete_token_btn = ttk.Button(self.tokens_frame, text="", image=self.delete_ico, width=3, command=self.delete_token)
        self.export_token_btn = ttk.Button(self.tokens_frame, image=self.export_ico, width=3, command=self.export_tokens)
        # Ligne 1 
        hostname_label = ttk.Label(self.frame, text="Hostname :")
        self.hostname_entry = ttk.Entry(self.frame)
        # Ligne 2 
        local_host_label = ttk.Label(self.frame, text="Hôte local :")
        self.host_entry = ttk.Entry(self.frame)
        self.host_entry.insert(0, "127.0.0.1")
        port_label_ssh = ttk.Label(self.frame, text="Port :")
        self.port_entry = ttk.Entry(self.frame, width=10)
        # Ligne 3
        self.use_token_var = tk.BooleanVar()
        self.use_token_check = ttk.Checkbutton(self.frame, text="Utiliser un Service Token", variable=self.use_token_var, command=self.toggle_token_fields)
        # Ligne 4 
        tokenid_label = ttk.Label(self.frame, text="Token ID :")
        self.token_id_entry = ttk.Entry(self.frame, state="disabled")
        # Ligne 5
        token_secret_label = ttk.Label(self.frame, text="Token Secret :")
        self.token_secret_entry = ttk.Entry(self.frame, state="disabled")
        # Ligne 6 
        self.use_proxy_var = tk.BooleanVar()
        self.use_proxy_check = ttk.Checkbutton(self.frame, text="Utiliser un Proxy", variable=self.use_proxy_var, command=self.toggle_proxy_fields)
        # Ligne 7
        proxy_label = ttk.Label(self.frame, text="Proxy :")
        self.proxy_entry = ttk.Entry(self.frame, state="disabled")
        # Ligne 8
        self.launch_button = ttk.Button(self.frame, text="Lancer la connexion", command=self.run_cloudflared)
        self.close_button = ttk.Button(self.frame, text="❌ Fermer connexion", command=self.close_connection)

        for i in range(9):
            match i:
                case i if i > 1 and i < 6:
                    pass
                case _:
                    # print(i)
                    self.frame.columnconfigure(i, weight=1)

        ################ - GRID - #################
        # ROW 0
        self.profile_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5,columnspan=4)
        self.tokens_frame.grid(row=0, column=5, sticky="ew", padx=5, pady=5,columnspan=2)
        # Profile
        self.profile_menu.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        self.new_profile_btn.grid(row=0, column=1, padx=(5, 2), sticky='w')
        self.save_btn.grid(row=0, column=2, padx=(2, 2), sticky='w')
        self.rename_profile_btn.grid(row=0, column=3, padx=(2, 2), sticky='w')
        self.import_btn.grid(row=0, column=4, padx=2, sticky='w')
        self.export_profile_btn.grid(row=0, column=5, padx=2, sticky='w')
        self.delete_profile_btn.grid(row=0, column=6, padx=(2, 5), sticky='w')
        # Tokens
        tokens_label.grid(row=0, column=6, sticky="e")
        self.token_menu.grid(row=0, column=7, sticky="ew", padx=2)
        self.add_tokens_button.grid(row=0, column=8, padx=(5, 2), sticky='w')
        self.save_tokens_button.grid(row=0, column=9, padx=2, sticky='w')
        self.rename_token_btn.grid(row=0, column=10, padx=(2, 2), sticky='w')
        self.import_tokens_button.grid(row=0, column=11, padx=2, sticky='w')
        self.export_token_btn.grid(row=0, column=12, padx=2, sticky='w')
        self.delete_token_btn.grid(row=0, column=13, padx=(2, 5), sticky='w')
        # 1 
        hostname_label.grid(row=1, column=0, sticky="e")
        self.hostname_entry.grid(row=1, column=1, columnspan=8, sticky="ew", padx=5, pady=5)
        # 2
        local_host_label.grid(row=2, column=0, sticky="e")
        self.host_entry.grid(row=2, column=1, sticky="ew", padx=5, pady=5)
        port_label_ssh.grid(row=2, column=2, sticky="e")
        self.port_entry.grid(row=2, column=3, sticky="w", padx=5, pady=5)
        # 3
        self.use_token_check.grid(row=3, columnspan=9, sticky="w", padx=5)
        # 4 
        tokenid_label.grid(row=4, column=0, sticky="e")
        self.token_id_entry.grid(row=4, column=1, columnspan=8, sticky="ew", padx=5, pady=5)
        # 5
        token_secret_label.grid(row=5, column=0, sticky="e")
        self.token_secret_entry.grid(row=5, column=1, columnspan=8, sticky="ew", padx=5, pady=5)
        # 6
        self.use_proxy_check.grid(row=6, columnspan=9, sticky="w", padx=5)
        # 7
        proxy_label.grid(row=7, column=0, sticky="e")
        self.proxy_entry.grid(row=7, column=1, columnspan=8, sticky="ew", padx=5, pady=5)
        # 8
        self.launch_button.grid(row=8,column=0, columnspan=6, pady=10,padx=(10,5),sticky='ew')
        self.close_button.grid(row=8,column=6, columnspan=7, pady=5,padx=(5,10),sticky='ew')
        ############################################

    def toggle_proxy_fields(self):
        """
        Active ou désactive les champs d'entrée des tokens en fonction de la case à cocher 'Utiliser un Service Token'.
        """
        state = "normal" if self.use_proxy_var.get() else "disabled"
        if state == "disabled":
            self.proxy_entry.delete(0, tk.END)
        self.proxy_entry.configure(state=state)

    def toggle_token_fields(self):
        """
        Active ou désactive les champs d'entrée des tokens en fonction de la case à cocher 'Utiliser un Service Token'.
        """
        state = "normal" if self.use_token_var.get() else "disabled"
        if state == "disabled":
            self.token_id_entry.delete(0, tk.END)
            self.token_secret_entry.delete(0, tk.END)
        self.token_id_entry.configure(state=state)
        self.token_secret_entry.configure(state=state)

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
        use_token = bool(str(config.get("token_id", "")))
        if use_token:
            self.use_token_var.set(True)
            self.toggle_token_fields()
            self.token_id_entry.delete(0, tk.END)
            self.token_secret_entry.delete(0, tk.END)
            self.token_id_entry.insert(0, config.get("token_id", ""))
            self.token_secret_entry.insert(0, config.get("token_secret", ""))
        else:
            self.use_token_var.set(False)
            self.toggle_token_fields()
        use_proxy = bool(str(config.get("proxy", "")))
        if use_proxy:
            self.use_proxy_var.set(True)
            self.toggle_proxy_fields()
            self.proxy_entry.delete(0, tk.END)
            self.proxy_entry.insert(0, config.get("proxy", ""))
        else:
            self.use_proxy_var.set(False)
            self.toggle_proxy_fields()


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
            "token_secret": self.token_secret_entry.get(),
            "proxy": self.proxy_entry.get()
        }
        write_json(CONFIG_FILE, PRESETS)
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
        write_json(TOKENS_FILE, TOKENS)
        self.token_menu['values'] = list(TOKENS.keys())
        timed_messagebox("Sauvegarde", f"Token '{name}' enregistré.")

    def import_config(self):
        """Importe un fichier JSON de profils cloudflared et l'ajoute aux profils locaux."""
        file_path = filedialog.askopenfilename(title="Importer un fichier de profils", filetypes=[("Fichiers JSON", "*.json")])
        if not file_path:
            return
        try:
            loaded = load_import_file(file_path)
        except Exception as e:
            messagebox.showerror("Import impossible", str(e))
            return
        PRESETS.update(loaded)
        write_json(CONFIG_FILE, PRESETS)
        self.profile_menu['values'] = list(PRESETS.keys())
        messagebox.showinfo("Import", f"Profils importés : {', '.join(loaded.keys())}")

    def import_tokens(self):
        """Importe un fichier JSON de tokens et l'ajoute aux tokens locaux."""
        file_path = filedialog.askopenfilename(title="Importer un fichier de tokens", filetypes=[("Fichiers JSON", "*.json")])
        if not file_path:
            return
        try:
            loaded = load_import_file(file_path)
        except Exception as e:
            messagebox.showerror("Import impossible", str(e))
            return
        TOKENS.update(loaded)
        write_json(TOKENS_FILE, TOKENS)
        self.token_menu['values'] = list(TOKENS.keys())
        messagebox.showinfo("Import", f"Tokens importés : {', '.join(loaded.keys())}")

    def export_json(self, data, title, initialfile, warning=None):
        if not data:
            messagebox.showwarning("Export", "Rien à exporter.")
            return
        if warning and not messagebox.askyesno("Export", warning):
            return
        file_path = filedialog.asksaveasfilename(
            title=title, defaultextension=".json", initialfile=initialfile,
            filetypes=[("Fichiers JSON", "*.json")])
        if not file_path:
            return
        try:
            write_json(file_path, data)
            timed_messagebox("Export", f"Export enregistré :\n{file_path}")
        except Exception as e:
            messagebox.showerror("Erreur d'export", f"Impossible d'exporter :\n{e}")

    def export_profile(self):
        """Exporte les profils cloudflared vers un fichier JSON."""
        self.export_json(
            PRESETS, "Exporter les profils cloudflared", "cloudflared_configs.json",
            "Les profils qui utilisent un service token contiennent son secret.\n"
            "Le fichier exporté contiendra ces secrets en clair. Continuer ?")

    def export_tokens(self):
        """Exporte les tokens vers un fichier JSON."""
        self.export_json(
            TOKENS, "Exporter les tokens", "cloudflared_tokens.json",
            "Le fichier exporté contiendra les secrets des tokens en clair. Continuer ?")

    def close_connection(self):
        prune_dead_connections()
        if not cloudflared_processes:
            timed_messagebox("Erreur", "Aucune connexion active à fermer.")
        elif len(cloudflared_processes) == 1:
            close_cloudflared_connection(cloudflared_processes[0])
        else:
            show_close_dialog()

    def run_cloudflared(self):
        """
        Lance cloudflared access tcp directement, sans shell intermédiaire.
        Le proxy et le service token passent par des variables d'environnement :
        rien n'est interprété par un shell et le secret n'apparaît pas dans la ligne de commande.
        """
        hostname = self.hostname_entry.get().strip()
        host = self.host_entry.get().strip() or "127.0.0.1"
        port = self.port_entry.get().strip()
        if not hostname or not port:
            messagebox.showerror("Erreur", "Hostname et Port doivent être renseignés.")
            return
        if not port.isdigit() or not 0 < int(port) < 65536:
            timed_messagebox("Erreur", "Le port spécifié n'est pas valide.")
            return
        url = f"{host}:{port}"

        path = self.cloudflared_path_var.get().strip()
        if not path or not os.path.isfile(path):
            timed_messagebox("Erreur", "Chemin vers cloudflared non valide.")
            return

        prune_dead_connections()
        if any(entry["url"] == url for entry in cloudflared_processes):
            timed_messagebox("Erreur", f"Une connexion est déjà active sur {url}. Veuillez choisir un autre port.")
            return
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, int(port)))
            except OSError:
                timed_messagebox("Port utilisé", f"Le port {port} est déjà utilisé localement. Veuillez en choisir un autre.")
                return

        env = os.environ.copy()
        for var in ("TUNNEL_SERVICE_TOKEN_ID", "TUNNEL_SERVICE_TOKEN_SECRET"):
            env.pop(var, None)
        if self.use_proxy_var.get():
            proxy = self.proxy_entry.get().strip()
            if not proxy:
                messagebox.showerror("Erreur", "Le Proxy doit être renseigné.")
                return
            proxy_url = proxy if "://" in proxy else f"http://{proxy}"
            for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
                env[var] = proxy_url

        token_name = ""
        if self.use_token_var.get():
            token_id = self.token_id_entry.get().strip()
            token_secret = self.token_secret_entry.get().strip()
            if not token_id or not token_secret:
                messagebox.showerror("Erreur", "Token ID et Secret doivent être renseignés.")
                return
            env["TUNNEL_SERVICE_TOKEN_ID"] = token_id
            env["TUNNEL_SERVICE_TOKEN_SECRET"] = token_secret
            token_name = self.token_menu.get() or "saisi à la main"

        cmd = [path, "access", "tcp", "--hostname", hostname, "--url", url]
        log_path = os.path.join(LOG_DIR, f"cloudflared-{time.strftime('%Y%m%d-%H%M%S')}-{port}.log")
        kwargs = {}
        if platform.system() == "Windows":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        else:
            kwargs["start_new_session"] = True
        try:
            with open(log_path, "ab") as log_file:
                proc = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL,
                                        stdout=log_file, stderr=subprocess.STDOUT, **kwargs)
        except Exception as e:
            messagebox.showerror("Erreur", f"Échec d'exécution : {e}")
            return

        entry = {"proc": proc, "hostname": hostname, "url": url, "token_name": token_name, "log_path": log_path}
        cloudflared_processes.append(entry)
        update_connection_status()
        # Vérification différée : l'interface n'est jamais bloquée.
        self.frame.after(1500, lambda: self.check_started(entry))

    def check_started(self, entry):
        proc = entry["proc"]
        if proc.poll() is None:
            timed_messagebox("Succès", f"Connexion vers {entry['hostname']} lancée.")
            return
        if entry in cloudflared_processes:
            cloudflared_processes.remove(entry)
        update_connection_status()
        try:
            with open(entry["log_path"], "r", encoding="utf-8", errors="replace") as f:
                tail = f.read()[-2000:]
        except OSError:
            tail = ""
        lowered = tail.lower()
        if "address already in use" in lowered or "only one usage of each socket address" in lowered:
            message = f"Le port {entry['url']} est déjà utilisé. Veuillez en choisir un autre."
        else:
            last_lines = "\n".join(tail.strip().splitlines()[-3:])
            message = f"cloudflared s'est arrêté (code {proc.returncode}).\n\n{last_lines}"
        messagebox.showerror("Échec de la connexion", message)

class CloudflaredGUI:
    def __init__(self, root):  # Main GUI initialization
        """
        Initialise l'interface principale, charge les profils, configure les onglets et les boutons.
        
        Args:
            root (tk.Tk): Fenêtre principale Tkinter.
        """
        self.root = root
        self.root.title(f"Gestionnaire Cloudflared TCP Tunnel v{VERSION}")
        self.root.resizable(True, True)
        self.root.minsize(760, 440)
        self.cloudflared_path_var = tk.StringVar()
        # Charger les profils AVANT d'ajouter des onglets
        self.load_configs_and_tokens()
        self.load_saved_cloudflared_path()
        self.detect_cloudflared()
        self.tabs,self.tab_count = [],0
        ## - WIDGET - ##
        self.top_frame = ttk.Frame(root)
        cloudflared_path_label = ttk.Label(self.top_frame, text="cloudflared :")
        self.path_entry = ttk.Entry(self.top_frame, textvariable=self.cloudflared_path_var, width=50)
        browse_cloudflared = ttk.Button(self.top_frame, text="Parcourir", command=self.browse_exe)
        download_cloudflard = ttk.Button(self.top_frame, text="Téléchargement", command=self.download_cloudflared)
        open_web_cloudflared = ttk.Button(self.top_frame, text="Page Cloudflare", command=self.open_download_page)
        # ONGLETS
        self.tab_control = ttk.Notebook(root)
        # BOTTOM FRAME
        self.button_frame = ttk.Frame(root)
        add_tab = ttk.Button(self.button_frame, text="Nouvel onglet", command=self.add_tab)
        remove_tab = ttk.Button(self.button_frame, text="Supprimer l'onglet", command=self.remove_current_tab)
        self.redirect_ssh_btn = ttk.Button(self.button_frame, text="🔐 Redirection SSH", command=self.open_ssh_redirector)
        self.status_label = ttk.Label(root, text="Connexions ouvertes : 0", anchor="e")
        self.status_label.bind("<Button-1>", self.on_status_click)
        ## - INIT - ##
        self.add_tab()
        ########### - GRID - #############
        self.root.geometry("900x360")
        self.top_frame.pack(fill="x", pady=5)
        cloudflared_path_label.pack(side="left", padx=5)
        self.path_entry.pack(side="left", padx=5)
        browse_cloudflared.pack(side="left", padx=(5,0))
        download_cloudflard.pack(side="left")
        open_web_cloudflared.pack(side="left")
        self.tab_control.pack(expand=1, fill="both")
        self.button_frame.pack(pady=5)
        add_tab.pack(side="left", padx=5)
        remove_tab.pack(side="left", padx=5)
        self.redirect_ssh_btn.pack(side="left", padx=5)
        self.status_label.pack(side="bottom", fill="x", padx=5, pady=2)
        ####################################
        self.root.geometry("760x440")
        self.root.after(2000, self.poll_processes)

    def open_ssh_redirector(self):
        self.redirect_ssh_btn.config(state="disabled")
        win = SSHRedirector(self.root)
    
        # Quand la fenêtre est fermée, réactiver le bouton
        win.top.protocol("WM_DELETE_WINDOW", lambda: self.on_close_ssh(win))

    def on_close_ssh(self, win):
        win.top.destroy()
        self.redirect_ssh_btn.config(state="normal")

    def on_status_click(self, event):
        show_close_dialog()

    def poll_processes(self):
        """Met à jour le compteur : un cloudflared arrêté de lui-même n'est plus compté."""
        update_connection_status()
        self.root.after(2000, self.poll_processes)

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
        system = platform.system()
        ext = ".exe" if system == "Windows" else ""
        dir = get_user_dir()
        path = filedialog.askopenfilename(
            title="Sélectionner cloudflared",
            filetypes=[("Executable", f"*{ext}")],initialfile="cloudflared-windows-amd64.exe", initialdir=dir)
        if path:
            self.cloudflared_path_var.set(path)
            self.save_cloudflared_path(path)

    def download_cloudflared(self):
        system = platform.system()
        urls = {
            "Windows": "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe",
            "Linux": "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64",
            "Darwin": "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-amd64.tgz",  # ou .zip si tu préfères
        }
        url = urls.get(system)
        if not url:
            messagebox.showerror("Erreur", f"Système non supporté : {system}")
            return

        save_ext = ".exe" if system == "Windows" else ""
        save_path = filedialog.asksaveasfilename(defaultextension=save_ext, filetypes=[("Executable", f"*{save_ext}")], title="Enregistrer cloudflared",
                                                 initialfile="cloudflared-windows-amd64.exe",initialdir=APPDATA_DIR)
        if not save_path:
            return

        try:
            urllib.request.urlretrieve(url, save_path)
            os.chmod(save_path, 0o755)  # Rendre exécutable sur Unix
            self.cloudflared_path_var.set(save_path)
            messagebox.showinfo("Téléchargement terminé", f"cloudflared téléchargé à :\n{save_path}")
        except Exception as e:
            messagebox.showerror("Erreur de téléchargement", f"Impossible de télécharger : {e}")

    def load_configs_and_tokens(self):
        """Charge les profils et les tokens dans `PRESETS` et `TOKENS`."""
        PRESETS.update(load_config_file(CONFIG_FILE))
        TOKENS.update(load_config_file(TOKENS_FILE))

    def save_cloudflared_path(self, path):
        """Sauvegarde le chemin vers cloudflared."""
        write_json(os.path.join(APPDATA_DIR, "cloudflared_path.json"), {"path": path})

    def load_saved_cloudflared_path(self):
        """Charge le chemin précédemment sauvegardé vers cloudflared."""
        save_file = os.path.join(APPDATA_DIR, "cloudflared_path.json")
        if os.path.exists(save_file):
            try:
                self.cloudflared_path_var.set(read_json(save_file).get("path", ""))
            except Exception:
                pass

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

class Tooltip:
    def __init__(self, widget, text="", font=('Arial', 8, 'bold'), padx=5, pady=3, wraplength=200):
        self.widget = widget
        self.text = text
        self.font = font
        self.padx = padx
        self.pady = pady
        self.wraplength = wraplength
        self.tooltip_window = None
        self.label = None

    def follow_mouse(self, event=None):
        if self.tooltip_window and event:
            self.tooltip_window.wm_geometry(f"+{event.x_root + 20}+{event.y_root + 10}")

    def set_text(self, new_text):
        self.text = new_text
        if self.label and self.label.winfo_exists():
            self.label.config(text=new_text)

    def show_tooltip(self, x, y):
        if self.tooltip_window or not self.text:
            return
        
        self.tooltip_window = tk.Toplevel(self.widget)
        self.tooltip_window.wm_overrideredirect(True)
        self.tooltip_window.wm_geometry(f"+{x+20}+{y+10}")
        
        self.label = tk.Label(
            self.tooltip_window,
            text=self.text,
            background="white",
            relief="solid",
            borderwidth=1,
            font=self.font,
            padx=self.padx,
            pady=self.pady,
            wraplength=self.wraplength
        )
        self.label.pack()

    def hide_tooltip(self):
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None

atexit.register(cleanup)
if __name__ == "__main__":
    root = tk.Tk()
    set_window_icon(root)
    app = CloudflaredGUI(root)
    if STARTUP_WARNINGS:
        root.after(200, lambda: messagebox.showwarning("Configuration", "\n\n".join(STARTUP_WARNINGS)))
    root.mainloop()
