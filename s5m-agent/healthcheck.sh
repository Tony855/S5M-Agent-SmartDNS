#!/bin/sh
set -eu

# Verify the Agent HTTP API responds. Credential mismatches must not make
# the container unhealthy or trigger unnecessary restarts.
wget -q -T 3 -O /dev/null http://127.0.0.1:80/api/config

# s6-overlay v3 does not ship the legacy s6-svstat command. Alpine BusyBox
# provides pidof; use it to verify the Mihomo dataplane process is present.
# The service supervisor remains responsible for restarting a crashed process.
pidof mihomo >/dev/null 2>&1
