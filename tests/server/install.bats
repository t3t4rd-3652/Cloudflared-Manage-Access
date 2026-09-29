#!/usr/bin/env bats
# Tests de server/install.sh. Ils modifient le système : ils ne tournent que dans un conteneur
# jetable (variable CMA_SERVER_TEST_CONTAINER=1 posée par tests/server/run-in-docker.sh).

setup_file() {
  export INSTALL="${BATS_TEST_DIRNAME}/../../server/install.sh"
  export TEST_USER="jean.dupont"
  if [[ "${CMA_SERVER_TEST_CONTAINER:-}" == "1" && "$(id -u)" -eq 0 ]]; then
    if ! getent passwd "$TEST_USER" >/dev/null; then
      if command -v useradd >/dev/null; then useradd -M "$TEST_USER"; else adduser -D -H "$TEST_USER"; fi
    fi
    # Faux binaire docker : publie le port 18080 pour le conteneur "web".
    printf '#!/bin/sh\necho "web 0.0.0.0:18080->80/tcp, :::18080->80/tcp"\n' > /usr/local/bin/docker
    chmod 755 /usr/local/bin/docker
  fi
}

teardown_file() {
  if [[ "${CMA_SERVER_TEST_CONTAINER:-}" == "1" && "$(id -u)" -eq 0 ]]; then
    rm -f /usr/local/bin/docker
  fi
}

setup() {
  if [[ "${CMA_SERVER_TEST_CONTAINER:-}" != "1" || "$(id -u)" -ne 0 ]]; then
    skip "réservé à un conteneur jetable lancé en root"
  fi
}

@test "refuse un utilisateur inexistant" {
  run bash "$INSTALL" --user nexistepas
  [ "$status" -ne 0 ]
  [[ "$output" == *"n'existe pas"* ]]
}

@test "refuse un nom d'utilisateur dangereux" {
  run bash "$INSTALL" --user 'x ALL=(ALL) NOPASSWD: ALL'
  [ "$status" -ne 0 ]
}

@test "--no-docker installe seulement ports-report" {
  run bash "$INSTALL" --no-docker --prefix "${BATS_TEST_TMPDIR}/prefix"
  [ "$status" -eq 0 ]
  [ -x "${BATS_TEST_TMPDIR}/prefix/bin/ports-report" ]
}

@test "installe le helper et une règle sudoers lisible par sudo malgré le point du nom" {
  run bash "$INSTALL" --user "$TEST_USER"
  [ "$status" -eq 0 ]
  [ -x /usr/local/bin/ports-report ]
  [ -x /usr/local/sbin/ports-report-docker-ps ]
  [ -f /etc/sudoers.d/ports-report-jean_dupont ]
  [ "$(stat -c '%a' /etc/sudoers.d/ports-report-jean_dupont)" = "440" ]
  run su -s /bin/sh "$TEST_USER" -c 'sudo -n /usr/local/sbin/ports-report-docker-ps'
  [ "$status" -eq 0 ]
  [[ "$output" == "web "* ]]
}

@test "l'installation est idempotente" {
  run bash "$INSTALL" --user "$TEST_USER"
  [ "$status" -eq 0 ]
  run bash "$INSTALL" --user "$TEST_USER"
  [ "$status" -eq 0 ]
  [ "$(find /etc/sudoers.d -name 'ports-report-*' | wc -l)" -eq 1 ]
}

@test "ports-report lancé par l'utilisateur voit le nom du conteneur" {
  python3 "${BATS_TEST_DIRNAME}/fixtures/services.py" &
  pid=$!
  for _ in $(seq 1 100); do ss -tln | grep -q ':18080 ' && break; sleep 0.1; done
  run su -s /bin/bash "$TEST_USER" -c '/usr/local/bin/ports-report --json --no-web'
  kill "$pid"
  [ "$status" -eq 0 ]
  [[ "${lines[0]}" == *'"docker":"helper"'* ]]
  [[ "$output" == *'"port":18080,'*'"container":"web"'* ]]
}

@test "--uninstall --user retire seulement la règle de cet utilisateur" {
  run bash "$INSTALL" --uninstall --user "$TEST_USER"
  [ "$status" -eq 0 ]
  [ ! -e /etc/sudoers.d/ports-report-jean_dupont ]
  [ -x /usr/local/bin/ports-report ]
}

@test "--uninstall sans --user retire tout" {
  run bash "$INSTALL" --uninstall
  [ "$status" -eq 0 ]
  [ ! -e /usr/local/bin/ports-report ]
  [ ! -e /usr/local/sbin/ports-report-docker-ps ]
}
