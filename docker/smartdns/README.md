# S5M SmartDNS image (DNS core only)

A small multi-stage Docker image built from the official [pymumu/smartdns](https://github.com/pymumu/smartdns) source. The optional SmartDNS Web UI is not built or included.

## Build inputs

- Default upstream source ref: `Release48.4` (override with `SMARTDNS_REF`).
- Build: Alpine Linux; SmartDNS C core only, with zlib support.
- Runtime: Alpine Linux plus the required runtime libraries and CA certificates.
- Architectures published by CI: `linux/amd64`, `linux/arm64`.
- License: SmartDNS is GPL-3.0-or-later. The image contains the upstream LICENSE, source commit SHA, and source URL under `/usr/share/licenses/smartdns/`. The corresponding source is available from the recorded commit in the upstream repository.

## Build locally

Run from the repository root:

```sh
docker buildx build \
  --platform linux/amd64 \
  --build-arg SMARTDNS_REF=Release48.4 \
  -f docker/smartdns/Dockerfile \
  -t smartdns:local docker/smartdns
```

For a local image load, use a single platform and add `--load`. A multi-platform image should be pushed to a registry.

## GHCR

The workflow `.github/workflows/smartdns-image.yml` builds and smoke-tests the AMD64 image on pull requests to `dev`. On pushes to `dev`, it builds and publishes a multi-platform manifest to:

- `ghcr.io/tony855/smartdns:dev`
- `ghcr.io/tony855/smartdns:latest`
- an immutable commit-SHA tag

A manual workflow run accepts an upstream SmartDNS ref. Manual publishing is opt-in.

## Run locally, safely

Use the example Compose file; it mounts `docker/smartdns/smartdns.conf` read-only, so edit that file or substitute your own config path if needed. It binds the host side to `127.0.0.1:6053`, keeping the service off public/LAN interfaces by default.

```sh
docker compose -f docker/smartdns/compose.example.yaml up -d
dig @127.0.0.1 -p 6053 example.com A
dig +tcp @127.0.0.1 -p 6053 example.com A
```

If Mihomo runs in another Docker container, connect both containers to the same user-defined Docker network and use `smartdns:53` as the DNS server address. A container's `127.0.0.1` is its own loopback, not the host's loopback.

Do not publish this recursive resolver to the public Internet without a deliberate access-control and abuse-prevention design. The sample only publishes a host-loopback port.

## CI tests

The smoke test starts a uniquely named temporary container, checks UDP and TCP DNS answers, and removes only that temporary container. It does not touch other containers, images, volumes, or host routes.
