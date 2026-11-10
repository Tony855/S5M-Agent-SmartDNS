#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

expected="21c940edc65520849ba03544c5cf8d9cf326e680"
dockerfile="docker/smartdns/Dockerfile"
workflow=".github/workflows/smartdns-image.yml"

grep -Fq "ARG SMARTDNS_COMMIT=${expected}" "$dockerfile"
grep -Fq 'git -C /src fetch --depth 1 origin "${SMARTDNS_COMMIT}"' "$dockerfile"
grep -Fq 'test "$(git -C /src rev-parse HEAD)" = "${SMARTDNS_COMMIT}"' "$dockerfile"
grep -Fq "SMARTDNS_COMMIT: ${expected}" "$workflow"
grep -Fq 'SMARTDNS_COMMIT=${{ env.SMARTDNS_COMMIT }}' "$workflow"
if grep -Eq 'SMARTDNS_REF|Release48\.4|smartdns_ref' "$dockerfile" "$workflow"; then
  echo "Mutable SmartDNS source reference remains in standalone image build" >&2
  exit 1
fi

echo "Standalone SmartDNS source is pinned to the verified immutable commit."
