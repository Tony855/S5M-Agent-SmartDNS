# S5M Agent + SmartDNS combined image

This is an **optional, standalone image variant** that runs the existing S5M Agent, Mihomo and SmartDNS in one container under s6-overlay supervision. This repository's `main` branch is the source of truth for this variant; it remains a separate image and does not replace the standard `s5m-agent` or RouterOS images.

- Image published after all required checks pass on a push to this repository's `main` branch: `ghcr.io/tony855/s5m-agent-smartdns:dev` plus a commit-SHA tag.
- Architectures: `linux/amd64` and `linux/arm64`.
- SmartDNS source: official `pymumu/smartdns`, pinned by the `Release48.4` tag; GPL-3.0-or-later license is included in the image.
- SmartDNS listens on container port `6053` (UDP and TCP). The combined Compose example does **not** publish this port to the host.
- The bundled SmartDNS configuration is dual-stack: IPv4 and IPv6 literal-IP DoT endpoints are retained in the default pool and dedicated `china-dot` group. IPv4-only egress can use IPv4 endpoints, IPv6-only egress can use IPv6 endpoints, and dual-stack egress can use both. The domestic group is exposed only on loopback `127.0.0.1:6054`; it includes AliDNS IPv4/IPv6 DoT and DNSPod IPv4 DoT, with TLS hostname validation and `-exclude-default-group`. The primary listener remains `127.0.0.1:6053`.
- Fresh Mihomo configs set `dns.nameserver-policy.geosite:cn` to `127.0.0.1:6054`, so mainland China domains use only the domestic DoT pool. Other domains continue through the existing `127.0.0.1:6053` resolver path. Bootstrap and proxy-server hostname lookups remain on literal-IP encrypted resolvers to avoid DNS recursion.
- The generated Mihomo `PROCESS-NAME,smartdns,<proxy>` rule routes SmartDNS upstream sockets through the selected proxy. Plaintext `server`/`server-tcp` upstream directives are rejected by Agent validation.
- Mihomo's fresh-install default config sends ordinary DNS queries to `127.0.0.1:6053`; bootstrap and proxy-server hostname lookups use literal-IP DNS servers to avoid a DNS loop.
- DNS cache ownership is intentionally split by responsibility, not duplicated: Mihomo `profile.store-fake-ip` persists Fake-IP-to-domain mappings needed to recognize later connections; it is not the DNS-answer cache. SmartDNS is the sole DNS-answer cache and owns `cache-size`, persistent cache, `prefetch-domain`, and `serve-expired`. Keep Mihomo's Fake-IP mapping persistence enabled while diagnosing stale DNS answers in SmartDNS.
- SmartDNS cache is explicitly persisted to `/data/smartdns.cache` on the Agent's `/data` volume, with a 3600-second checkpoint interval; this avoids relying on SmartDNS's automatic disk-space-based persistence decision and keeps the cache alongside the Agent's durable data.
- All DoT upstreams must set both `-host-name` (TLS SNI) and matching `-tls-host-verify` (certificate hostname validation), including controller-generated per-client upstreams. Never silently disable certificate verification.
- The S5M controller's Agent management page reports SmartDNS availability, process status, DNS query probe health, version, config hash and error details. The **SmartDNS 配置** action edits and queues a config command over the existing authenticated Agent WebSocket; the Agent validates the candidate, persists it in `/data/smartdns.conf`, restarts only SmartDNS, and reports the result. After heartbeat confirms SmartDNS UDP/TCP probes are healthy, the controller automatically routes Mihomo's ordinary `dns.nameserver` queries to `127.0.0.1:6053`; bootstrap and proxy-server name resolution remain on literal-IP resolvers. The selected resolver is persisted in the node config to avoid repeated config delivery.
- SmartDNS is restricted to `127.0.0.1:6053` over UDP and TCP. The controller rejects configs that change these listeners or include arbitrary `include`/`exec` directives.
- The standard `s5m-agent` and RouterOS images are not replaced by this variant.

## Try it after the image is published

Copy `docker-compose.example.yml` to a separate test directory and review port mappings before starting it. It uses its own container name and its own `./data` directory. Do not point it at the data directory of an existing Agent unless you intentionally want to reuse that Agent's configuration and state.

Build locally from the repository root:

```sh
docker build --platform linux/amd64 \
  --build-arg SMARTDNS_REF=Release48.4 \
  -f s5m-agent/Dockerfile.smartdns \
  -t s5m-agent-smartdns:local .
```

## Existing Agent migration

The init script intentionally preserves a non-empty `/data/config.yaml`. Therefore, changing the image does not silently rewrite an existing node's DNS settings. To enable SmartDNS for an existing Agent, back up the config first and explicitly set the Mihomo `dns.nameserver` to `127.0.0.1:6053`; keep `default-nameserver` and `proxy-server-nameserver` on reachable literal-IP resolvers to avoid bootstrap loops. Validate with `mihomo -t -d /data -f /data/config.yaml` before restarting.

## Tests and image publishing

The dedicated GitHub Actions workflow runs on relevant pull requests targeting `main` and pushes to `main`. It runs server and Agent tests, builds AMD64 and ARM64 images, exercises Mihomo fallback selection and fail-closed behavior on both architectures, starts a temporary combined container on each architecture, checks Agent HTTP health and both dataplane processes, verifies that no proxy or controller API port is published, confirms restart persistence and SmartDNS self-recovery where supported, and performs UDP and TCP DNS lookups against both default and China-only SmartDNS listeners.

Pull-request runs do not publish images. The multi-architecture image is published only after the `test-server`, AMD64 runtime smoke, and ARM64 build/runtime smoke jobs all pass on a push to `main`. The `dev` suffix is a GHCR image tag; it is not the Git branch name.
