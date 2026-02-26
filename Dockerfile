# Multi-stage build: compile Go binaries, then copy to minimal runtime
FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /phoenix-server ./cmd/phoenix-server/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /phoenix ./cmd/phoenix/

# Runtime image — minimal, no shell needed for server
FROM alpine:3.21

RUN apk add --no-cache ca-certificates wget

COPY --from=builder /phoenix-server /usr/local/bin/phoenix-server
COPY --from=builder /phoenix /usr/local/bin/phoenix

RUN adduser -D -u 1000 phoenix
USER phoenix

VOLUME /data
EXPOSE 9090

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -q --spider http://localhost:9090/v1/health || exit 1

ENTRYPOINT ["phoenix-server"]
CMD ["--config", "/data/config.json"]
