# syntax=docker/dockerfile:1
# Agent Fileserver MCP service. Caddy runs from the official caddy image; see compose.yaml.

FROM golang:1.27.3-alpine3.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY *.go ./
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.buildVersion=${VERSION}" \
      -o /out/agent-fileserver .

FROM alpine:3.24.2
# brotli precompresses published assets; nothing else is needed at runtime.
RUN apk add --no-cache brotli \
 && addgroup -g 10001 afs \
 && adduser -D -H -u 10001 -G afs -s /sbin/nologin afs \
 && install -d -o 10001 -g 10001 -m 0750 /run/agent-fileserver-api \
 && install -d -o 10001 -g 10001 -m 0755 /var/lib/agent-fileserver
COPY --from=build /out/agent-fileserver /usr/local/bin/agent-fileserver
ENV FSERVER_ROOT=/var/lib/agent-fileserver
USER 10001:10001
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["agent-fileserver", "healthcheck", "--socket", "/run/agent-fileserver-api/http.sock"]
ENTRYPOINT ["agent-fileserver"]
CMD ["serve", "--socket", "/run/agent-fileserver-api/http.sock"]
