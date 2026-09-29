#!/usr/bin/env bash
# Lance les tests bats des scripts serveur dans des conteneurs jetables.
#   tests/server/run-in-docker.sh                 # Debian (mawk), Ubuntu, Alpine (busybox awk)
#   tests/server/run-in-docker.sh debian:13-slim  # une seule image
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
HOST_ROOT="$ROOT"
if command -v cygpath >/dev/null 2>&1; then
  HOST_ROOT="$(cygpath -m "$ROOT")"   # Git Bash sous Windows
fi
export MSYS_NO_PATHCONV=1

if (($#)); then IMAGES=("$@"); else IMAGES=(debian:13-slim ubuntu:24.04 alpine:3.20); fi

status=0
for image in "${IMAGES[@]}"; do
  case "$image" in
    alpine*) prepare='apk add --no-cache bash bats iproute2 curl python3 sudo shadow coreutils >/dev/null' ;;
    *) prepare='apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq bats iproute2 curl python3 sudo >/dev/null' ;;
  esac
  echo "=== ${image} ==="
  if ! docker run --rm -e CMA_SERVER_TEST_CONTAINER=1 -v "${HOST_ROOT}:/src:ro" "$image" \
      sh -c "${prepare} && readlink -f \$(command -v awk) && bats /src/tests/server"; then
    status=1
  fi
done
exit "$status"
