# proxy-auto-rotate-forwarder

A zero-dependency Go forward proxy that rotates HTTP and CONNECT traffic
through a pool of upstream proxies (`http` / `https` / `socks5`), rotating
past failures with per-proxy cooldowns.

```bash
# quickstart
cp configs/proxies.example.txt configs/proxies.txt   # edit: your proxies
LISTEN_ADDR=:8080 ADMIN_ADDR=127.0.0.1:8081 go run ./cmd/proxy-auto-rotate-forwarder

curl -x http://127.0.0.1:8080 https://example.com/
curl http://127.0.0.1:8081/status
```

Full operator docs, env reference, and behavior notes: [AGENTS.md](AGENTS.md).
