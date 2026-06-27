FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" -o /portreach .

# OCI labels: org.opencontainers.image.source links the ghcr package to this
# repo (which makes ghcr show the repo README and "About" metadata) — the ghcr
# equivalent of Docker Hub's separate description push.
FROM alpine:3.21 AS alpine
LABEL org.opencontainers.image.source="https://github.com/lavr/portreach" \
      org.opencontainers.image.description="Distributed network reachability checker (per-node probe + web aggregator)" \
      org.opencontainers.image.licenses="MIT"
RUN apk add --no-cache ca-certificates
COPY --from=build /portreach /usr/local/bin/portreach
ENTRYPOINT ["portreach"]

FROM scratch AS rootless
LABEL org.opencontainers.image.source="https://github.com/lavr/portreach" \
      org.opencontainers.image.description="Distributed network reachability checker (per-node probe + web aggregator)" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /portreach /portreach
USER 65534:65534
ENTRYPOINT ["/portreach"]
