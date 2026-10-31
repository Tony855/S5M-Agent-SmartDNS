# S5M Next Docker deployment

## Files and persistence

- `s5m-data` stores SQLite, generated config and application backups under `/data/s5m-server`.
- `mihomo-config` is reserved for Mihomo's runtime config.
- The management service runs as an unprivileged user, drops Linux capabilities, uses a read-only root filesystem and does not publish the Mihomo controller port.
- The management UI is exposed on host port `18081` by default. This is separate from the legacy S5M service.

## Start

```sh
cp .env.example .env
# Edit .env and replace all placeholder secrets. Do not commit .env.
docker compose config
docker compose up -d --build
docker compose ps
curl -fsS http://127.0.0.1:18081/api/v1/health
```

## Logs / stop / update

```sh
docker compose logs --tail=200 -f s5m-server
docker compose pull mihomo
docker compose up -d --build
docker compose down
```

`docker compose down -v` deletes persistent data volumes and must not be used for routine updates.

## Important limitations

This Compose file provides an isolated management container and Mihomo container, but does not automatically enable TUN or transparent proxying. Configure host routing and add only the required `NET_ADMIN` capability and `/dev/net/tun` device after validating the intended traffic path. The current Go app's Mihomo config path and runtime volume conventions should be verified against the selected deployment mode before enabling config publishing. On a low-memory production host, build the image elsewhere and deploy the resulting image to avoid exhausting disk/RAM.
