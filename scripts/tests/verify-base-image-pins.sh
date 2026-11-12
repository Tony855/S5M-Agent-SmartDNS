#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

declare -A expected=(
  ["s5m-agent/Dockerfile"]="alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf"
  ["s5m-agent/Dockerfile.smartdns"]="alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf"
  ["s5m-agent/Dockerfile.routeros"]="alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf"
  ["docker/smartdns/Dockerfile"]="alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f"
)

for file in "${!expected[@]}"; do
  [[ -f "$file" ]] || { echo "Missing Dockerfile: $file" >&2; exit 1; }
  expected_line="ARG ALPINE_IMAGE=${expected[$file]}"
  grep -Fqx "$expected_line" "$file" || {
    echo "$file must declare the verified immutable base: $expected_line" >&2
    exit 1
  }
  if grep -Eq '^FROM[[:space:]]+alpine:' "$file"; then
    echo "$file contains an unpinned Alpine FROM reference" >&2
    exit 1
  fi
  if grep -E '^FROM[[:space:]]' "$file" | grep -Fv '${ALPINE_IMAGE}' >/dev/null; then
    echo "$file contains a FROM reference outside the pinned ALPINE_IMAGE" >&2
    exit 1
  fi
done

echo "All Agent and SmartDNS Dockerfiles use verified multi-architecture Alpine manifest digests."
