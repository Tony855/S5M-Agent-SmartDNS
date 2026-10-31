# S5M Agent + SmartDNS

Independent repository for the S5M Agent combined image with Mihomo and SmartDNS.

- Image: `ghcr.io/tony855/s5m-agent-smartdns:dev`
- Architectures: Linux AMD64 and ARM64
- Runtime: s6-overlay supervises Agent, Mihomo and SmartDNS
- SmartDNS listener: container loopback `127.0.0.1:6053` (UDP/TCP)
- Persistent data: `/data`

## Build

```sh
docker build --platform linux/amd64 --build-arg SMARTDNS_REF=Release48.4 -f s5m-agent/Dockerfile.smartdns -t s5m-agent-smartdns:local .
```

See [SmartDNS guide](s5m-agent/smartdns/README.md), [installation](docs/INSTALLATION_GUIDE_CN.md), [deployment](docs/DEPLOYMENT_GUIDE_CN.md), and [Agent API contract](docs/AGENT_API_CONTRACT.md).

The S5M Master server remains in [S5M-Master](https://github.com/Tony855/S5M-Master).
