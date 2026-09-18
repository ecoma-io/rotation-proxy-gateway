# Multi-stage build. Runtime stage is `scratch`: exactly one static binary
# plus the CA bundle used to verify HTTPS targets reached through SOCKS5.
# No shell — the Docker HEALTHCHECK works because `rotation-proxy-gateway
# healthcheck` is a binary subcommand of the entrypoint itself.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY . .
ARG VERSION=0.1.0-dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -buildvcs=false \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/rotation-proxy-gateway ./cmd/rotation-proxy-gateway

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/rotation-proxy-gateway /app/rotation-proxy-gateway
USER 65532:65532
EXPOSE 30120 30121 30122 30123
ENTRYPOINT ["/app/rotation-proxy-gateway"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD ["/app/rotation-proxy-gateway", "healthcheck"]
