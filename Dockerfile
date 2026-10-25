# Multi-stage build: compile Go binaries, then copy to minimal runtime.
#
# The builder always runs on the build machine's own platform and
# cross-compiles for TARGETARCH, so multi-arch builds (buildx
# --platform linux/amd64,linux/arm64) do not run the Go compiler under QEMU.
# The default below only matters for the legacy (non-BuildKit) builder,
# which does not set BUILDPLATFORM; BuildKit always sets it.
ARG BUILDPLATFORM=linux/amd64
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder
ARG TARGETOS=linux
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w" -o /phoenix-server ./cmd/phoenix-server/
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w" -o /phoenix ./cmd/phoenix/

# Runtime image — minimal alpine; busybox wget is used by the healthcheck.
FROM alpine:3.21

RUN apk add --no-cache ca-certificates

COPY --from=builder /phoenix-server /usr/local/bin/phoenix-server
COPY --from=builder /phoenix /usr/local/bin/phoenix

# /data must exist and belong to the runtime user BEFORE the VOLUME line:
# a fresh named volume copies this ownership. Without it, the first-run
# `--init /data` fails with "permission denied" (VOLUME alone creates a
# root-owned directory).
RUN adduser -D -u 1000 phoenix && mkdir -p /data && chown phoenix:phoenix /data && chmod 700 /data
USER phoenix

VOLUME /data
EXPOSE 9090

# Probe whichever transport the config uses: plain HTTP (default) or TLS.
# --no-check-certificate is fine here: this only asks "is the process
# answering on its own loopback", it never sends a token.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -q --spider http://127.0.0.1:9090/v1/health || wget -q --spider --no-check-certificate https://127.0.0.1:9090/v1/health || exit 1

ENTRYPOINT ["phoenix-server"]
CMD ["--config", "/data/config.json"]
