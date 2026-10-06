#!/usr/bin/env bash
set -euo pipefail
python3 -m unittest discover -s tests -v
actionlint .github/workflows/ci.yml
shellcheck scripts/check.sh
zizmor --offline action.yml .github/workflows/ci.yml
