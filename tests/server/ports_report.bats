#!/usr/bin/env bats
# Tests de server/ports-report. Lancement : tests/server/run-in-docker.sh

setup_file() {
  export PR="${BATS_TEST_DIRNAME}/../../server/ports-report"
  python3 "${BATS_TEST_DIRNAME}/fixtures/services.py" &
  echo $! > "${BATS_FILE_TMPDIR}/services.pid"
  for _ in $(seq 1 100); do
    if ss -tln | grep -q ':18080 ' && ss -tln | grep -q ':18022 '; then break; fi
    sleep 0.1
  done
}

teardown_file() {
  kill "$(cat "${BATS_FILE_TMPDIR}/services.pid")" 2>/dev/null || true
}

line_for_port() {
  printf '%s\n' "$output" | grep "\"port\":$1,"
}

@test "aucune fin de ligne CRLF dans les scripts serveur" {
  # « ! commande » ne fait pas échouer un test bats : on échoue explicitement.
  if grep -q $'\r' "$PR"; then false; fi
  if grep -q $'\r' "${BATS_TEST_DIRNAME}/../../server/install.sh"; then false; fi
}

@test "--version affiche la version" {
  run bash "$PR" --version
  [ "$status" -eq 0 ]
  [[ "$output" == "ports-report 2."* ]]
}

@test "une option inconnue est refusée" {
  run bash "$PR" --nope
  [ "$status" -eq 2 ]
}

@test "JSON : chaque ligne est un objet JSON valide" {
  run bash "$PR" --json
  [ "$status" -eq 0 ]
  printf '%s\n' "$output" | python3 -c 'import json, sys; [json.loads(l) for l in sys.stdin if l.strip()]'
}

@test "JSON : la première ligne décrit le script" {
  run bash "$PR" --json
  [ "$status" -eq 0 ]
  [[ "${lines[0]}" == '{"v":2,"meta":{"version":"2.'* ]]
}

@test "JSON : le port HTTP est détecté avec son adresse d'écoute" {
  run bash "$PR" --json
  [ "$status" -eq 0 ]
  line="$(line_for_port 18080)"
  [[ "$line" == *'"bind":["127.0.0.1"]'* ]]
  [[ "$line" == *'"scheme":"http"'* ]]
  [[ "$line" == *'"http_code":200'* ]]
}

@test "JSON : un service non HTTP n'a ni schéma ni code" {
  run bash "$PR" --json
  [ "$status" -eq 0 ]
  line="$(line_for_port 18022)"
  [[ "$line" == *'"bind":["0.0.0.0"]'* ]]
  [[ "$line" == *'"scheme":null'* ]]
  [[ "$line" == *'"http_code":null'* ]]
}

@test "texte : format historique compatible avec CMA 1.x" {
  run bash "$PR"
  [ "$status" -eq 0 ]
  [[ "$output" == *"tcp 18080 - HTTP 200"* ]]
  [[ "$output" == *"tcp 18022 - -"* ]]
}

@test "--exclude retire un port" {
  run bash "$PR" --json --exclude 18022
  [ "$status" -eq 0 ]
  [[ "$output" != *'"port":18022,'* ]]
  [[ "$output" == *'"port":18080,'* ]]
}

@test "PORTS_REPORT_EXCLUDE retire un port" {
  PORTS_REPORT_EXCLUDE=18080 run bash "$PR" --json
  [ "$status" -eq 0 ]
  [[ "$output" != *'"port":18080,'* ]]
}

@test "--no-web désactive la sonde HTTP" {
  run bash "$PR" --json --no-web
  [ "$status" -eq 0 ]
  [[ "${lines[0]}" == *'"web_probe":false'* ]]
  [[ "$(line_for_port 18080)" == *'"scheme":null'* ]]
}

@test "exécution par l'entrée standard, comme le fait CMA 2.x" {
  run bash -c "bash -s -- --json < '$PR'"
  [ "$status" -eq 0 ]
  [[ "$(line_for_port 18080)" == *'"http_code":200'* ]]
}
