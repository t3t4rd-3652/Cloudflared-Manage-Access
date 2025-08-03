import paramiko
import subprocess
import os
from pathlib import Path

def ssh_key_exists():
    print(Path.home().joinpath(".ssh", "id_ed25519"))
    return Path.home().joinpath(".ssh", "id_ed25519").exists()

def generate_ssh_key():
    print("[+] Génération d'une nouvelle clé SSH...")
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", str(Path.home() / ".ssh/id_ed25519"), "-N", ""])


def send_ssh_key_to_server(host, port, username):
    from paramiko import SSHClient, AutoAddPolicy
    from paramiko.ed25519key import Ed25519Key

    pubkey_path = Path.home() / ".ssh" / "id_ed25519.pub"
    with open(pubkey_path, "r") as f:
        pubkey = f.read().strip()

    print(f"[+] Connexion à {username}@{host}:{port} pour ajouter la clé...")

    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    password = input("Mot de passe SSH (temporaire, pour envoyer la clé) : ")

    ssh.connect(hostname=host, port=port, username=username, password=password)

    # Créer ~/.ssh si nécessaire
    ssh.exec_command("mkdir -p ~/.ssh && chmod 700 ~/.ssh")
    
    # Ajouter la clé dans authorized_keys
    ssh.exec_command(f'echo "{pubkey}" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys')
    
    print("[✓] Clé SSH ajoutée avec succès !")
    ssh.close()


def get_remote_listening_ports(host, port, username):
    ports = []
    try:
        key_path = str(Path.home() / ".ssh/id_ed25519")
        private_key = paramiko.Ed25519Key(filename=key_path)

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, port=port, username=username, pkey=private_key)

        stdin, stdout, stderr = client.exec_command("ss -tuln | grep LISTEN")
        lines = stdout.readlines()

        for line in lines:
            parts = line.split()
            if len(parts) >= 5:
                address = parts[4]
                if ":" in address:
                    port = address.split(":")[-1]
                    ports.append(port)

        client.close()
        return sorted(set(ports))
    except Exception as e:
        print(f"[!] Erreur SSH : {e}")
        return []

def create_ssh_tunnel(remote_host, ssh_user, ssh_port, remote_port, local_port):
    cmd = [
        "ssh",
        "-p", str(ssh_port),
        "-N",
        "-L", f"{local_port}:localhost:{remote_port}",
        f"{ssh_user}@{remote_host}"
    ]
    print(f"\n[+] Tunnel : localhost:{local_port} → {remote_host}:{remote_port} (via SSH port {ssh_port})")
    print("[i] Ctrl+C pour arrêter le tunnel.")
    subprocess.run(cmd)

if __name__ == "__main__":
    remote_host = input("Adresse IP ou nom d'hôte du serveur distant : ").strip()
    ssh_port = input("Port SSH (défaut 22) : ").strip()
    ssh_port = int(ssh_port) if ssh_port else 22
    ssh_user = input("Nom d'utilisateur SSH : ").strip()

    # Vérifie s’il existe une clé SSH
    if not ssh_key_exists():
        choice = input("[?] Aucune clé SSH trouvée. Veux-tu en générer une maintenant ? (o/n) : ").strip().lower()
        if choice == "o":
            generate_ssh_key()
            send_ssh_key_to_server(remote_host, ssh_port, ssh_user)
        else:
            print("[!] Opération annulée, clé requise pour continuer.")
            exit(1)
    else:
        print("[✓] Clé SSH détectée.")

    print("\n[.] Connexion SSH et récupération des ports ouverts...")
    ports = get_remote_listening_ports(remote_host, ssh_port, ssh_user)

    if not ports:
        print("[!] Aucun port trouvé ou échec de connexion.")
        exit(1)

    print("\n[+] Ports en écoute sur le serveur :")
    for i, port in enumerate(ports):
        print(f"  {i+1}. Port {port}")

    choice = input("\nQuel port distant veux-tu rediriger ? (ex: 25565) : ")
    if choice not in ports:
        print("[!] Port invalide.")
        exit(1)

    local_port = input("Sur quel port local veux-tu accéder à ce service ? (ex: 25565) : ")
    create_ssh_tunnel(remote_host, ssh_user, ssh_port, choice, local_port)
