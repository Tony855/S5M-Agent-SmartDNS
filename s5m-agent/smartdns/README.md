# S5M Agent + SmartDNS combined image

This is an **optional, standalone image variant** that runs the existing S5M Agent, Mihomo and SmartDNS in one container under s6-overlay supervision. Its development branch is `s5m-agent-smartdns`; it is intentionally not merged into `main` or `dev`.

- Image published by a successful push to the isolated `s5m-agent-smartdns` branch: `ghcr.io/tony855/s5m-agent-smartdns:dev` plus a commit-SHA tag.
- Architectures: `linux/amd64` and `linux/arm64`.
- SmartDNS source: official `pymumu/smartdns`, pinned by the `Release48.4` tag; GPL-3.0-or-later license is included in the image.
- SmartDNS listens on container port `6053` (UDP and TCP). The combined Compose example does **not** publish this port to the host.
- Mihomo's fresh-install default config sends ordinary DNS queries to `127.0.0.1:6053`; bootstrap and proxy-server hostname lookups use literal-IP DNS servers to avoid a DNS loop.
- The S5M controller's Agent management page reports SmartDNS availability, process status, DNS query probe health, version, config hash and error details. The **SmartDNS 配置** action edits and queues a config command over the existing authenticated Agent WebSocket; the Agent validates the candidate, persists it in `/data/smartdns.conf`, restarts only SmartDNS, and reports the result.
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

The dedicated GitHub Actions workflow is triggered by relevant file changes in a pull request targeting `s5m-agent-smartdns` or by a push to `s5m-agent-smartdns`. It builds AMD64, starts a temporary combined container, checks Agent HTTP health and both dataplane processes, verifies the mixed proxy port, and performs UDP and TCP DNS lookups. It separately builds the ARM64 image.

Pull-request runs do not publish images. The multi-architecture image is published only after a successful **push to `s5m-agent-smartdns`** (the branch's `dev` image tag is a container tag, not the Git branch named `dev`). Pushing to the repository's `dev` branch alone does not trigger this workflow.
