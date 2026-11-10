#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

mapfile -t action_lines < <(grep -RhoE '^[[:space:]]*(- )?uses:[[:space:]]*[^[:space:]]+([[:space:]]+#.*)?$' .github/workflows)
if (("${#action_lines[@]}" == 0)); then
  echo "No GitHub Actions references found" >&2
  exit 1
fi

for line in "${action_lines[@]}"; do
  ref="${line#*uses: }"
  ref="${ref%%#*}"
  ref="${ref%%[[:space:]]*}"
  [[ -n "$ref" ]] || { echo "Empty action reference: $line" >&2; exit 1; }
  [[ "$ref" == ./* ]] && continue
  if [[ ! "$ref" =~ @([0-9a-f]{40})$ ]]; then
    echo "Third-party Action is not pinned to a full commit SHA: $ref" >&2
    exit 1
  fi
done

echo "All external GitHub Actions are pinned to immutable 40-character commits."
