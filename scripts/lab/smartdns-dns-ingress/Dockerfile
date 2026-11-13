FROM alpine:3.24
RUN apk add --no-cache ca-certificates libgcc libstdc++ libssl3 libcrypto3 zlib iproute2 python3
COPY .runtime/smartdns /usr/sbin/smartdns
COPY smartdns-per-client.conf /etc/smartdns/smartdns.conf
ENTRYPOINT ["/usr/sbin/smartdns", "-f", "-c", "/etc/smartdns/smartdns.conf"]
COPY socks-observer.py /usr/local/bin/socks-observer.py
