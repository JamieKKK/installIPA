#!/bin/zsh
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p ipas

if [[ -f ".env.oss" ]]; then
  set -a
  source ".env.oss"
  set +a
fi

python3 tools/ios_ota_publish.py --serve "$@"
