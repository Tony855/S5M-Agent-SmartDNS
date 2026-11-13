FROM alpine:3.24
RUN apk add --no-cache ca-certificates
COPY .runtime/smartdns /usr/sbin/smartdns
COPY smartdns-per-client.conf /etc/smartdns/smartdns.conf
ENTRYPOINT ["/usr/sbin/smartdns", "-f", "-c", "/etc/smartdns/smartdns.conf"]
