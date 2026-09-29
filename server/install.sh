#!/usr/bin/env bash
# install.sh : installe ports-report sur un serveur Linux et, en option, le helper qui
# permet à des utilisateurs choisis de lire les noms des conteneurs Docker sans droits docker.
#
#   sudo ./install.sh --user alice [--user bob] [--no-docker] [--prefix /usr/local]
#   sudo ./install.sh --uninstall [--user alice]
#
# Le script est idempotent : le relancer remet l'installation dans l'état attendu.
# Documentation : docs/SERVEUR.md.
set -Eeuo pipefail
trap 'echo "install.sh : erreur à la ligne $LINENO" >&2' ERR

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="${SCRIPT_DIR}/ports-report"
PREFIX="/usr/local"
HELPER="/usr/local/sbin/ports-report-docker-ps"
SUDOERS_DIR="/etc/sudoers.d"
ACTION="install"
WITH_DOCKER="auto"
USERS=()

usage() {
  cat <<'USAGE'
Usage :
  sudo ./install.sh --user NOM [--user NOM...] [--no-docker] [--prefix CHEMIN]
  sudo ./install.sh --uninstall [--user NOM...]

  --user NOM     utilisateur autorisé à lire les noms des conteneurs Docker via le helper
  --no-docker    installer seulement ports-report, sans helper Docker ni règle sudoers
  --prefix       préfixe d'installation de ports-report (défaut : /usr/local)
  --uninstall    retirer l'installation. Avec --user, retire seulement les règles de ces
                 utilisateurs ; sans --user, retire tout.
USAGE
}

die() { echo "install.sh : $*" >&2; exit 1; }

while (($#)); do
  case "$1" in
    --user) shift; [[ -n "${1:-}" ]] || die "--user attend un nom d'utilisateur."; USERS+=("$1") ;;
    --user=*) USERS+=("${1#*=}") ;;
    --no-docker) WITH_DOCKER="no" ;;
    --prefix) shift; PREFIX="${1:-}" ;;
    --prefix=*) PREFIX="${1#*=}" ;;
    --uninstall) ACTION="uninstall" ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "option inconnue : $1" ;;
  esac
  shift
done

[[ "${EUID}" -eq 0 ]] || die "lancez ce script avec sudo."
[[ -n "$PREFIX" && "$PREFIX" == /* ]] || die "--prefix doit être un chemin absolu."
BIN="${PREFIX}/bin/ports-report"

# Les noms passent dans une règle sudoers : on refuse tout caractère inattendu.
for user in ${USERS[@]+"${USERS[@]}"}; do
  [[ "$user" =~ ^[a-z_][a-z0-9_.-]*$ ]] || die "nom d'utilisateur refusé : '$user'."
  getent passwd "$user" >/dev/null || die "l'utilisateur '$user' n'existe pas sur ce système."
done

# sudo ignore les fichiers de /etc/sudoers.d dont le nom contient un point.
sudoers_file() { echo "${SUDOERS_DIR}/ports-report-${1//./_}"; }

if [[ "$ACTION" == "uninstall" ]]; then
  if ((${#USERS[@]})); then
    for user in "${USERS[@]}"; do
      rm -f "$(sudoers_file "$user")"
      echo "Règle sudoers retirée pour ${user}."
    done
  else
    rm -f "${SUDOERS_DIR}"/ports-report-* "$HELPER" "$BIN"
    echo "ports-report, le helper Docker et toutes les règles sudoers associées ont été retirés."
  fi
  exit 0
fi

[[ -f "$SOURCE" ]] || die "fichier introuvable : ${SOURCE}"
if grep -q $'\r' "$SOURCE"; then
  die "${SOURCE} a des fins de ligne Windows (CRLF). Convertissez-le : sed -i 's/\r\$//' ${SOURCE}"
fi

install -d -m 0755 "${PREFIX}/bin"
install -m 0755 -o root -g root "$SOURCE" "$BIN"
echo "ports-report installé : ${BIN} ($("$BIN" --version))."

if [[ "$WITH_DOCKER" == "no" ]]; then
  echo "Helper Docker non installé (--no-docker)."
  exit 0
fi

DOCKER_BIN="$(command -v docker || true)"
if [[ -z "$DOCKER_BIN" ]]; then
  echo "Docker n'est pas installé : helper Docker non installé."
  exit 0
fi
if ((${#USERS[@]} == 0)); then
  echo "Aucun --user fourni : helper Docker non installé."
  echo "Relancez avec --user NOM pour autoriser un utilisateur à lire les noms des conteneurs."
  exit 0
fi
command -v visudo >/dev/null || die "visudo introuvable : installez le paquet sudo."

# Helper root : ne renvoie que "NomConteneur Ports", en lecture seule.
install -d -m 0755 "$(dirname "$HELPER")"
helper_tmp="$(mktemp)"
cat > "$helper_tmp" <<HELPER_EOF
#!/bin/sh
# Installé par ports-report/install.sh : liste en lecture seule des conteneurs et de leurs ports.
exec ${DOCKER_BIN} ps --format '{{.Names}} {{.Ports}}'
HELPER_EOF
install -m 0755 -o root -g root "$helper_tmp" "$HELPER"
rm -f "$helper_tmp"
echo "Helper Docker installé : ${HELPER}."

for user in "${USERS[@]}"; do
  target="$(sudoers_file "$user")"
  rule_tmp="$(mktemp)"
  echo "${user} ALL=(root) NOPASSWD: ${HELPER}" > "$rule_tmp"
  if ! visudo -cf "$rule_tmp" >/dev/null; then
    rm -f "$rule_tmp"
    die "la règle sudoers générée pour ${user} est invalide."
  fi
  install -m 0440 -o root -g root "$rule_tmp" "$target"
  rm -f "$rule_tmp"
  echo "Règle sudoers écrite pour ${user} : ${target}."
done

echo
echo "Installation terminée."
echo "Vérification côté utilisateur : sudo -n ${HELPER} (doit lister les conteneurs sans mot de passe)."
