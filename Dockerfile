# Multi-stage build. Runtime stage is `scratch`: exactly one static binary
# plus the CA bundle used to verify HTTPS targets reached through SOCKS5.
# No shell — the Docker HEALTHCHECK works because `proxy-auto-rotate-forwarder
# healthcheck` is a binary subcommand of the entrypoint itself.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -buildvcs=false \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/proxy-auto-rotate-forwarder ./cmd/proxy-auto-rotate-forwarder

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/proxy-auto-rotate-forwarder /app/proxy-auto-rotate-forwarder
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app/proxy-auto-rotate-forwarder"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD ["/app/proxy-auto-rotate-forwarder", "healthcheck"]
