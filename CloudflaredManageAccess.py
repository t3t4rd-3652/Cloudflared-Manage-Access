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

################ - VARIABLES - ######################

APPDATA_DIR = get_appdata_dir()
os.makedirs(APPDATA_DIR, exist_ok=True)
SSH_KEY_DIR = Path(APPDATA_DIR) / "ssh_keys"
SSH_KEY_DIR.mkdir(parents=True, exist_ok=True)

active_paramiko_connections = {}
cloudflared_processes = []
connection_labels = []
active_ssh_tunnels = []
ssh_keys_summary = []

CONFIG_FILE = os.path.join(APPDATA_DIR, "cloudflared_configs.json")
TOKENS_FILE = os.path.join(APPDATA_DIR, "cloudflared_tokens.json")
SSH_REDIR_FILE = os.path.join(APPDATA_DIR, "cloudflared_ssh_redir.json")

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
# BOUTON ADD
add_ico = Image.open(r"ico\add.png")
add_ico = add_ico.resize((15, 15))       
# BOUTON DELETE
delete_ico = Image.open(r"ico\delete.png")
delete_ico = delete_ico.resize((15, 15))
# BOUTON EDIT
edit_ico = Image.open(r"ico\edit.png")
edit_ico = edit_ico.resize((15, 15))
# BOUTON EXPORT
export_ico = Image.open(r"ico\export.png")
export_ico = export_ico.resize((15, 15))
# BOUTON IMPORT
import_ico = Image.open(r"ico\import.png")
import_ico = import_ico.resize((15, 15))
# BOUTON SAVE
save_ico = Image.open(r"ico\save.png")
save_ico = save_ico.resize((15, 15))

################################################

def forward_tunnel(local_port, remote_host, remote_port, transport):
    """Écoute sur local_port et transfère vers remote_port via transport Paramiko."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', local_port))
    sock.listen(1)
    try:
        while True:
            client_socket, addr = sock.accept()
            chan = transport.open_channel(
                "direct-tcpip",
                (remote_host, remote_port),
                addr
            )
            threading.Thread(target=transfer, args=(client_socket, chan), daemon=True).start()
    except Exception as e:
        print(f"[Tunnel fermé] {e}")
    finally:
        sock.close()

def transfer(src, dst):
    """Transfert bidirectionnel de données entre deux sockets."""
    while True:
        data = src.recv(1024)
        if not data:
            break
        dst.send(data)
    src.close()
    dst.close()

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
    top = tk.Toplevel()
    top.title(title)
    top.geometry("400x100")
    top.resizable(False, False)
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
        self.top.title("Redirection SSH")
        self.top.geometry("420x630")
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
            print(f"[INFO] Réutilisation connexion: {host}:{port} ({user})")
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
        try:
            ssh.connect(hostname=host, port=port, username=username, password=password)
            ssh.exec_command("mkdir -p ~/.ssh && chmod 700 ~/.ssh")
            ssh.exec_command(f'echo "{pubkey}" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys')
            ssh.close()
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
        port = int(self.port_entry_ssh.get().strip())
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
        port = int(self.port_entry_ssh.get().strip())
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
                try:
                    stdin, stdout, stderr = client.exec_command("ports-report")
                    # print('ports-report')
                except Exception as e:
                    print(e)             
                    messagebox.showwarning("Le binaire ports-report n'est pas disponible sur le serveur, veuillez l'installer.")
                    stdin, stdout, stderr = client.exec_command("ss -tuln | grep LISTEN")

                output = stdout.readlines()
                self.ports_listbox.delete(0, tk.END)
                self.ports_info = []
                try:
                    for line in output:
                        parts = line.split()
                        if parts:
                            protocol = parts[0]
                            port_ssh = parts[1]
                            service = parts[2]
                            match len(parts):
                                case 5:
                                    code_name = parts[3];code_int = parts[4]
                                    total_code = code_name + " " + code_int
                                    match code_int:
                                        case '200':
                                            final_code = code_name + f' ✅'
                                        case '-':
                                            final_code = ' ❓'; total_code = "Protocol non HTTP"
                                        case "302":
                                            final_code = ' ❓'
                                        case "301":
                                            final_code = ' ❓'
                                        case _:
                                            if parts[2] == '-':
                                                service = 'WebApp'
                                            final_code = code_name + f' ❌'
                                case 4:
                                    total_code = "HTTP Access Denied"
                                    final_code = " ❌"
                                case 6:
                                    if service == 'http-alt':
                                        service = 'WebApp'
                                    code_name = parts[-2];code_int = parts[-1]
                                    total_code = code_name + " " + code_int
                                    final_code = " ❌" if code_int != "301" else '❓'
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
        port = int(self.port_entry_ssh.get().strip())
        user = self.user_entry_ssh.get().strip()
        selected = self.ports_listbox.curselection()
        if not selected:
            messagebox.showwarning("Aucun port sélectionné", "Veuillez sélectionner un port distant à rediriger.")
            return
        selected_text = self.ports_listbox.get(selected[0])
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
                        "-L", f"{local_port}:localhost:{remote_port}", f"{user}@{host}"]
                try:
                    startupinfo = None
                    if platform.system() == "Windows":
                        startupinfo = subprocess.STARTUPINFO()
                        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

                    proc = subprocess.Popen(cmd, startupinfo=startupinfo)
                    active_ssh_tunnels.append((f"{user}:{remote_port} → localhost:{local_port} {user}@{host}:{port}", proc))
                    self.refresh_connection_list()
                    messagebox.showinfo("Tunnel actif", f"""L'adresse localhost:{local_port} redirige le port {remote_port}\nde la connexion {user}@{host}:{port}""")
                except Exception as e:
                    messagebox.showerror("Erreur de tunnel", str(e))


        else:
            client = self.init_connection(host,port,user)
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
                    print(f"[Tunnel] Écoute sur 127.0.0.1:{local_port} vers {remote_host}:{remote_port} (distant)")
                    while not stop_event.is_set():
                        try:
                            sock.settimeout(1)  # permet de vérifier stop_event régulièrement
                            client_sock, addr = sock.accept()
                        except socket.timeout:
                            continue
                        print(f"[Tunnel] Connexion reçue depuis {addr}")
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

            active_ssh_tunnels.append((f"{user}:{remote_port} → localhost:{local_port} {user}@{host}:{port}", client,stop_event))
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
        try:
            part_url = active_ssh_tunnels[self.conn_listbox.curselection()[0]][0].split(" ")[2]
            # print(active_ssh_tunnels[self.conn_listbox.curselection()[0]][0].split(" ")[2])
            part_http = "http://"
            url = part_http + part_url
            webbrowser.open(url)
        except Exception as e:
            messagebox.showinfo(f"La page web n'a pas pu être ouverte: {e}")
        # webbrowser.open()

    def refresh_key_list(self):
        self.keys_listbox.delete(0, tk.END)
        for path in ssh_keys_summary:
            self.keys_listbox.insert(tk.END, path)
    
    def load_configs_ssh(self):
        """
        Charge les fichiers JSON existants contenant les profils et les tokens.
        Met à jour les variables globales `PRESETS` et `TOKENS`.
        """
        global SSH_REDIR
        if os.path.exists(SSH_REDIR_FILE):
            with open(SSH_REDIR_FILE, "r") as f:
                SSH_REDIR.update(json.load(f))
        self.profile_redirect['values'] = list(SSH_REDIR.keys())

    def load_profile_ssh(self, event=None):
        name = self.profile_redirect_var.get()
        config = SSH_REDIR.get(name, {})
        self.host_entry_ssh.delete(0, tk.END)
        self.host_entry_ssh.insert(0, config.get("host", "localhost"))
        self.port_entry_ssh.delete(0, tk.END)
        self.port_entry_ssh.insert(0, config.get("port", ""))
        self.user_entry_ssh.delete(0, tk.END)
        self.user_entry_ssh.insert(0, config.get("user", ""))

    def save_config_ssh(self):
        """
        Sauvegarde le profil de connexion courant dans le fichier JSON de configuration.
        Affiche une boîte d'information à la fin.
        """
        name = self.profile_redirect_var.get()
        if not name:
            return
        SSH_REDIR[name] = {
            "host": self.host_entry_ssh.get(),
            "port": self.port_entry_ssh.get(),
            "user": self.user_entry_ssh.get(),
        }
        with open(SSH_REDIR_FILE, "w") as f:
            json.dump(SSH_REDIR, f, indent=2)
        self.profile_redirect['values'] = list(SSH_REDIR.keys())
        timed_messagebox("Sauvegarde", f"Configuration SSH '{name}' enregistrée.")

    def add_config_ssh(self):
        name = simpledialog.askstring("Nouveau token", "Nom du nouveau token :")
        if name and name not in SSH_REDIR:
            SSH_REDIR[name] = {}
            self.profile_redirect['values'] = list(SSH_REDIR.keys())
            self.profile_redirect_var.set(name)

    def delete_profile_ssh(self): #A MODIF
        name = self.profile_redirect_var.get()
        if name not in SSH_REDIR:
            return
        confirm = messagebox.askyesno("Supprimer", f"Supprimer le profil '{name}' ?")
        if confirm:
            del SSH_REDIR[name]
            self.profile_redirect['values'] = list(PRESETS.keys())
            self.profile_redirect_var.set('')
            with open(SSH_REDIR_FILE, "w") as f:
                json.dump(SSH_REDIR, f, indent=2)

    def rename_profile_ssh(self): #A modif
        name = self.profile_redirect_var.get()
        # print(name not in TOKENS)
        if name not in SSH_REDIR:
            return
        new_name = simpledialog.askstring("Renommer le token", "Nouveau nom :", initialvalue=name)
        if new_name and new_name != name:
            SSH_REDIR[new_name] = SSH_REDIR.pop(name)
            self.profile_redirect['values'] = list(TOKENS.keys())
            self.profile_redirect_var.set(new_name)
            with open(SSH_REDIR_FILE, "w") as f:
                json.dump(SSH_REDIR, f, indent=2)
    
    def import_profile_ssh(self):
        """
        Importe un fichier JSON contenant des tokens.
        Met à jour la liste des tokens et sauvegarde dans le fichier local.
        """
        file_path = filedialog.askopenfilename(title="Importer un fichier de tokens", filetypes=[("Fichiers JSON", "*.json")])
        if not file_path:
            return
        with open(file_path, "r") as f:
            loaded = json.load(f)
            SSH_REDIR.update(loaded)
            self.profile_redirect['values'] = list(TOKENS.keys())
            imported_names = ', '.join(loaded.keys())
            with open(SSH_REDIR_FILE, "w") as f_tokens:
                json.dump(SSH_REDIR, f_tokens, indent=2)
            messagebox.showinfo("Import", f"Tokens importés : {imported_names}")
            self.profile_redirect['values'] = list(SSH_REDIR.keys())

    def export_profile_ssh(self):
        """
        Exporte le dictionnaire SSH_REDIR (tokens/redirections SSH) vers un fichier JSON choisi par l'utilisateur.
        """
        try:
            if not SSH_REDIR:
                messagebox.showwarning("Export", "Aucun token/redirection SSH à exporter (SSH_REDIR est vide).")
                return

            file_path = filedialog.asksaveasfilename(
                title="Exporter les tokens/redirections SSH",
                defaultextension=".json",
                initialfile="cloudflared_ssh_redir.json",
                filetypes=[("Fichiers JSON", "*.json")]
            )
            if not file_path:
                return

            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(SSH_REDIR, f, indent=2, ensure_ascii=False)

            # Si tu as timed_messagebox, utilise-le, sinon messagebox classique
            try:
                timed_messagebox("Export", f"Tokens SSH exportés vers :\n{file_path}")
            except NameError:
                messagebox.showinfo("Export", f"Tokens SSH exportés vers :\n{file_path}")

        except Exception as e:
            messagebox.showerror("Erreur d'export", f"Impossible d'exporter les tokens SSH :\n{e}")


    # def test(self):
    #     dir_picture = resource_path("ico") 
    #     data = os.listdir(dir_picture)
    #     timed_messagebox("TEST",f"{data}")


##
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
        # LIGNE 0 
        # PART PROFILE ##########RAJOUTER EXPORT
        self.profile_var = tk.StringVar(value="Default")
        self.profile_menu = ttk.Combobox(self.frame, textvariable=self.profile_var, state="readonly")
        self.profile_menu.bind("<<ComboboxSelected>>", self.load_profile)
        self.import_btn = ttk.Button(self.frame, text="Importer", command=self.import_config)
        self.save_btn = ttk.Button(self.frame, text="Sauvegarder", command=self.save_config)
        self.new_profile_btn = ttk.Button(self.frame, text="➕", width=3, command=self.create_new_profile)
        self.rename_profile_btn = ttk.Button(self.frame, text="✏️", width=3, command=self.rename_profile)
        self.delete_profile_btn = ttk.Button(self.frame, text="🗑️", width=3, command=self.delete_profile)
        self.export_profile_btn = ttk.Button(self.frame) ### A FAIRE
        #- PART TOKEN ##########RAJOUTER EXPORT
        tokens_label = ttk.Label(self.frame, text="Tokens :")
        self.token_profile_var = tk.StringVar(value="")
        self.token_menu = ttk.Combobox(self.frame, textvariable=self.token_profile_var, state="readonly")
        self.token_menu.bind("<<ComboboxSelected>>", self.load_token_profile)
        self.import_tokens_button = ttk.Button(self.frame, text="Importer", command=self.import_tokens)
        self.save_tokens_button = ttk.Button(self.frame, text="Sauvegarder", command=self.save_token)
        self.add_tokens_button = ttk.Button(self.frame, text="➕", width=3, command=self.create_new_token_profile)
        self.rename_token_btn = ttk.Button(self.frame, text="✏️", width=3, command=self.rename_token)
        self.delete_token_btn = ttk.Button(self.frame, text="🗑️", width=3, command=self.delete_token)
        self.export_token_btn = ttk.Button(self.frame) # A FAIRE 
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
        self.profile_menu.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        self.import_btn.grid(row=0, column=1, padx=2, sticky='ew')
        self.save_btn.grid(row=0, column=2, padx=(0, 2), sticky='ew')
        self.new_profile_btn.grid(row=0, column=3, padx=(0, 5), sticky='ew')
        self.rename_profile_btn.grid(row=0, column=4, padx=(0, 2), sticky='ew')
        self.delete_profile_btn.grid(row=0, column=5, padx=(0, 5), sticky='w')
        tokens_label.grid(row=0, column=6, sticky="e")
        self.token_menu.grid(row=0, column=7, sticky="ew", padx=2)
        self.import_tokens_button.grid(row=0, column=8, padx=2, sticky='ew')
        self.save_tokens_button.grid(row=0, column=9, padx=2, sticky='ew')
        self.add_tokens_button.grid(row=0, column=10, padx=(0, 5), sticky='w')
        self.rename_token_btn.grid(row=0, column=11, padx=(0, 2), sticky='ew')
        self.delete_token_btn.grid(row=0, column=12, padx=(0, 5), sticky='w')
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
        self.launch_button.grid(row=6,column=0, columnspan=6, pady=10,padx=(10,5),sticky='ew')
        self.close_button.grid(row=6,column=6, columnspan=7, pady=5,padx=(5,10),sticky='ew')
        ############################################

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
            
    def export_profile(self):
        """
        Exporte le dictionnaire PRESTS (profils cloudflared) vers un fichier JSON choisi par l'utilisateur.
        """
        try:
            if not PRESETS:
                messagebox.showwarning("Export", "Aucun profil à exporter (PRESETS est vide).")
                return

            file_path = filedialog.asksaveasfilename(
                title="Exporter les profils cloudflared",
                defaultextension=".json",
                initialfile="cloudflared_configs.json",
                filetypes=[("Fichiers JSON", "*.json")]
            )
            if not file_path:
                return

            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(PRESETS, f, indent=2, ensure_ascii=False)

            try:
                timed_messagebox("Export", f"Profils exportés vers :\n{file_path}")
            except NameError:
                messagebox.showinfo("Export", f"Profils exportés vers :\n{file_path}")

        except Exception as e:
            messagebox.showerror("Erreur d'export", f"Impossible d'exporter les profils :\n{e}")

    def export_tokens(self):
        """
        Exporte le dictionnaire PRESTS (profils cloudflared) vers un fichier JSON choisi par l'utilisateur.
        """
        try:
            if not TOKENS:
                messagebox.showwarning("Export", "Aucun Tokens à exporter (TOKENS est vide).")
                return

            file_path = filedialog.asksaveasfilename(
                title="Exporter les profils cloudflared",
                defaultextension=".json",
                initialfile="cloudflared_tokens.json",
                filetypes=[("Fichiers JSON", "*.json")]
            )
            if not file_path:
                return

            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(TOKENS, f, indent=2, ensure_ascii=False)

            try:
                timed_messagebox("Export", f"Profils exportés vers :\n{file_path}")
            except NameError:
                messagebox.showinfo("Export", f"Profils exportés vers :\n{file_path}")

        except Exception as e:
            messagebox.showerror("Erreur d'export", f"Impossible d'exporter les profils :\n{e}")

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
            dialog.resizable(False, False)
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
        """
        Lance la commande cloudflared avec les paramètres fournis par l'utilisateur.
        Gère l'utilisation ou non d'un token.
        Affiche une boîte de dialogue en cas d’erreur ou de succès.
        """
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
            startupinfo = None
            if platform.system() == "Windows":
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
        # self.root.geometry("900x340")
        # self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.resizable(False, False)
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
        download_cloudflard = ttk.Button(self.top_frame, text="Téléchargement direct", command=self.download_cloudflared)
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
        self.root.geometry("900x340")
        self.top_frame.pack(fill="x", pady=5)
        cloudflared_path_label.pack(side="left", padx=5)
        self.path_entry.pack(side="left", padx=5)
        browse_cloudflared.pack(side="left", padx=5)
        download_cloudflard.pack(side="left")
        open_web_cloudflared.pack(side="left")
        self.tab_control.pack(expand=1, fill="both")
        self.button_frame.pack(pady=5)
        add_tab.pack(side="left", padx=5)
        remove_tab.pack(side="left", padx=5)
        self.redirect_ssh_btn.pack(side="left", padx=5)
        self.status_label.pack(side="bottom", fill="x", padx=5, pady=2)
        ####################################

    def open_ssh_redirector(self):
        self.redirect_ssh_btn.config(state="disabled")
        win = SSHRedirector(self.root)
    
        # Quand la fenêtre est fermée, réactiver le bouton
        win.top.protocol("WM_DELETE_WINDOW", lambda: self.on_close_ssh(win))

    def on_close_ssh(self, win):
        win.top.destroy()
        self.redirect_ssh_btn.config(state="normal")

    def on_status_click(self, event):
        def confirm_and_close_V2(index):
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
        try:
            dialog = tk.Toplevel()
            dialog.title("Fermer une connexion")
            dialog.geometry("500x260")
            dialog.resizable(False, False)
            ttk.Label(dialog, text="Sélectionnez une connexion à fermer :").pack(pady=10)
            listbox = tk.Listbox(dialog, width=80)
            listbox.pack(padx=10, pady=5, fill="both", expand=True)
            for i, p in enumerate(cloudflared_processes):
                hostname = next((arg for j, arg in enumerate(p.args) if p.args[j-1] == '--hostname'), f"Connexion {i}")
                url = next((arg for j, arg in enumerate(p.args) if p.args[j-1] == '--url'), f"Connexion {i}")
                try:
                    token_ = next((arg for j, arg in enumerate(p.args) if p.args[j-1] == '--service-token-id'))
                    # print(token_)
                    if token_:
                        token_name = hostname.split(".")[0]
                        token = f"| Token sélectionné: {token_name}"
                except:
                    token = ""
                listbox.insert(tk.END, f"{hostname} → {url} {token} ")

            def on_select():
                selected = listbox.curselection()
                if selected:
                    confirm_and_close_V2(selected[0])

            ttk.Button(dialog, text="Fermer la connexion sélectionnée", command=on_select).pack(pady=10)
            dialog.attributes('-topmost', True)
            dialog.grab_set()
        except Exception as e:
            messagebox.showerror("Erreur lors de la supression: ", e)

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
        # print(save_file)
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
    root.iconbitmap(resource_path(r"ico\cloudflared.ico"))
    app = CloudflaredGUI(root)
    root.mainloop()
