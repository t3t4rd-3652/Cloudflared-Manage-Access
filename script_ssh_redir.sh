#!/usr/bin/env bash
set -Eeuo pipefail

# --- Demande du login utilisateur ---
read -rp "Utilisateur autorisé à lancer ports-report (ex: alice) : " TARGET_USER
if [[ -z "${TARGET_USER}" ]]; then
  echo "Erreur: aucun utilisateur fourni." >&2; exit 1
fi
if ! getent passwd "${TARGET_USER}" >/dev/null; then
  echo "Erreur: l'utilisateur '${TARGET_USER}' n'existe pas sur ce système." >&2
  exit 1
fi

# --- Chemins / constantes ---
HELPER="/usr/local/sbin/ports-report-docker-ps"
SUDOERS_FILE="/etc/sudoers.d/ports-report-${TARGET_USER}"
PORTS_REPORT="/usr/local/bin/ports-report"

# --- 1) Helper root: lecture seule de 'docker ps' (noms/ports) ---
sudo tee "${HELPER}" >/dev/null <<'SH'
#!/bin/sh
# Renvoie uniquement "NomConteneur Ports" (lecture seule)
exec /usr/bin/docker ps --format '{{.Names}} {{.Ports}}'
SH
sudo chown root:root "${HELPER}"
sudo chmod 755 "${HELPER}"

# --- 2) Règle sudoers ciblée (seulement ce helper, sans mot de passe) ---
#    -> on met une entrée dédiée par utilisateur pour éviter les collisions
echo "${TARGET_USER} ALL=(root) NOPASSWD: ${HELPER}" | sudo tee "${SUDOERS_FILE}" >/dev/null
sudo chmod 440 "${SUDOERS_FILE}"
if ! sudo visudo -cf "${SUDOERS_FILE}" >/dev/null; then
  echo "Erreur: la validation sudoers a échoué (${SUDOERS_FILE})." >&2
  sudo rm -f "${SUDOERS_FILE}" || true
  exit 1
fi

# --- 3) Script /usr/local/bin/ports-report (version avec helper intégré) ---
sudo tee "${PORTS_REPORT}" >/dev/null <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

DEBUG=${DEBUG:-0}
[[ "$DEBUG" = "1" ]] && set -x
trap 'echo "Erreur à la ligne $LINENO" >&2' ERR

cmdv() { command -v "$1" 2>/dev/null || true; }

PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/bin"
export PATH

DOCKER=$(cmdv docker)
SS=$(cmdv ss)
AWK=$(cmdv awk)
GETENT=$(cmdv getent)
SORT=$(cmdv sort)
XARGS=$(cmdv xargs)
PRINTF=$(cmdv printf)
CURL=$(cmdv curl)
MKTEMP=$(cmdv mktemp)

[[ -n "${SS}"     ]] || { echo "Erreur: 'ss' introuvable."; exit 1; }
[[ -n "${AWK}"    ]] || { echo "Erreur: 'awk' introuvable."; exit 1; }
[[ -n "${GETENT}" ]] || { echo "Erreur: 'getent' introuvable."; exit 1; }
[[ -n "${SORT}"   ]] || { echo "Erreur: 'sort' introuvable."; exit 1; }
[[ -n "${XARGS}"  ]] || { echo "Erreur: 'xargs' introuvable."; exit 1; }
[[ -n "${PRINTF}" ]] || { echo "Erreur: 'printf' introuvable."; exit 1; }
[[ -n "${MKTEMP}" ]] || { echo "Erreur: 'mktemp' introuvable."; exit 1; }

NPROC=${NPROC:-64}
declare -A MAP

# Ports à exclure
EXCLUDE_PORTS=("5355" "5357" "45475" "20241")

# --- Source Docker "lecture seule" : helper root si dispo, sinon docker ps, sinon rien ---
get_docker_ps_stream() {
  local HELPER="/usr/local/sbin/ports-report-docker-ps"

  if [[ -n "$HELPER" ]]; then
    # -n : non-interactif (échoue si pas autorisé, sans demander de mot de passe)
    /usr/bin/sudo  -n "$HELPER" 2>/dev/null || true
  elif [[ -n "${DOCKER}" ]]; then
    "$DOCKER" ps --format '{{.Names}} {{.Ports}}' 2>/dev/null || true
  else
    true
  fi
}

# --- Map Docker (toujours tenter; si rien n'est dispo, la boucle ne lira rien) ---
while IFS= read -r line; do
  name="${line%% *}"; ports="${line#* }"
  IFS=, read -ra items <<< "$ports"
  for item in "${items[@]:-}"; do
    [[ -n "${item:-}" ]] || continue
    item="$($XARGS <<< "$item")"
    if [[ "$item" =~ :([0-9]+)(-([0-9]+))?\-\>[0-9]+(-([0-9]+))?/(tcp|udp) ]]; then
      host_lo="${BASH_REMATCH[1]}"
      host_hi="${BASH_REMATCH[3]:-${host_lo}}"
      proto="${BASH_REMATCH[6]}"
      for ((hp=host_lo; hp<=host_hi; hp++)); do
        key="${proto}:${hp}"
        if [[ -n "${MAP[$key]:-}" && "${MAP[$key]}" != *"$name"* ]]; then
          MAP[$key]="${MAP[$key]},$name"
        else
          MAP[$key]="$name"
        fi
      done
    fi
  done
done < <(get_docker_ps_stream)

check_web() {
  local port="$1" code=""
  [[ -n "${CURL}" ]] || { echo "-"; return 0; }

  code="$("$CURL" -s -o /dev/null -w "%{http_code}" \
         --connect-timeout 0.5 --max-time 1 \
         "http://127.0.0.1:${port}" 2>/dev/null || true)"
  if [[ -n "$code" && "$code" != "000" ]]; then
    echo "HTTP $code"; return 0
  fi

  code="$("$CURL" -k -s -o /dev/null -w "%{http_code}" \
         --connect-timeout 0.5 --max-time 1.5 \
         "https://127.0.0.1:${port}" 2>/dev/null || true)"
  if [[ -n "$code" && "$code" != "000" ]]; then
    echo "HTTPS $code"; return 0
  fi

  echo "-"
}

MAIN_PID=$$
TMPDIR="$("$MKTEMP" -d)"
trap '[[ $$ -eq '"$MAIN_PID"' ]] && rm -rf "$TMPDIR" || true' EXIT

jobgate() {
  while (( $(jobs -rp | wc -l) >= NPROC )); do
    wait -n 2>/dev/null || sleep 0.05
  done
}

declare -A SEEN

while read -r proto port; do
  [[ "$proto" != "tcp" ]] && continue   # seulement TCP

  # Exclusions
  for p in "${EXCLUDE_PORTS[@]}"; do
    [[ "$port" == "$p" ]] && continue 2
  done

  key="${proto}:${port}"
  [[ -n "${SEEN[$key]:-}" ]] && continue
  SEEN[$key]=1

  svc="$("$GETENT" services "${port}/${proto}" | "$AWK" '{print $1}' || true)"
  [[ -z "$svc" ]] && svc="inconnu"
  [[ "$port" == "5201" ]] && svc="iperf3"   # override

  cname="${MAP[$key]:-"-"}"

  jobgate
  (
    trap - EXIT ERR
    set +e
    web="$(check_web "$port")"

    if [[ "$cname" != "-" ]]; then
      "$PRINTF" "%s %s %s %s\n" "$proto" "$port" "$cname" "$web" > "$TMPDIR/${proto}_${port}.line"
    elif [[ "$svc" != "inconnu" ]]; then
      "$PRINTF" "%s %s %s - %s\n" "$proto" "$port" "$svc" "$web" > "$TMPDIR/${proto}_${port}.line"
    else
      "$PRINTF" "%s %s - %s\n" "$proto" "$port" "$web" > "$TMPDIR/${proto}_${port}.line"
    fi
  ) &
done < <(
  "$SS" -tuln | "$AWK" '
  /LISTEN|UNCONN/ {
    proto=$1
    local=""
    for (i=1;i<=NF;i++){
      if ($i ~ /:[0-9]+$/) { local=$i }
    }
    if (local=="") next
    gsub(/%[a-zA-Z0-9_.:-]+/, "", local)
    port=""
    if (match(local, /:([0-9]+)$/, m)) { port=m[1] }
    if (port!="") { print proto, port }
  }'
)

wait
cat "$TMPDIR"/*.line 2>/dev/null | "$SORT" -k2,2n || true
EOF

sudo chown root:root "${PORTS_REPORT}"
sudo chmod 750 "${PORTS_REPORT}"

# --- 4) ACL: lecture + exécution du script pour l'utilisateur choisi ---
sudo setfacl -m u:${TARGET_USER}:r-x "${PORTS_REPORT}"

echo
echo "=== Vérification ACL sur ${PORTS_REPORT} ==="
sudo getfacl "${PORTS_REPORT}" | sed -n '1,99p'

# Test de validation: la ligne 'user:TARGET_USER:r-x' doit être présente
if sudo getfacl "${PORTS_REPORT}" | grep -qE "^user:${TARGET_USER}:r-x$"; then
  echo "OK: ACL appliquée pour ${TARGET_USER} (r-x)."
else
  echo "ECHEC: l'ACL r-x pour ${TARGET_USER} n'apparaît pas. Vérifie le mask ou réessaie." >&2
  exit 1
fi

echo
echo "Installation terminée."
echo "- ${HELPER} est disponible (root) et autorisé pour ${TARGET_USER} via ${SUDOERS_FILE}."
echo "- ${PORTS_REPORT} est exécutable par ${TARGET_USER}."
echo
echo "Utilisation côté ${TARGET_USER}:"
echo "  ports-report"
echo
echo "Si sudo demande un mot de passe, assure-toi que la règle sudoers est bien prise en compte (nouvelle session)."
EOF
