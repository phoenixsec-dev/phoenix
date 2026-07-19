#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
scenario_start 12 onepassword-bridge
skip "external 1Password credentials are intentionally excluded; run only in a separately authorized synthetic vault"
