# syntax=docker/dockerfile:1.7
# Run with --network host: the proxy cores bind many TCP/UDP ports and the
# relay forwards need the real interfaces. Cores are downloaded into the
# data volume on first start, so the image itself stays small.

FROM --platform=$BUILDPLATFORM node:24-alpine AS web
RUN corepack enable && corepack prepare pnpm@9 --activate
WORKDIR /src/web/ui
COPY web/ui/package.json web/ui/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ui/ ./
RUN pnpm build

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH VERSION=docker
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
COPY --from=web /src/web/ui/dist web/ui/dist
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /out/bosun ./cmd/bosun

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/bosun /usr/local/bin/bosun
COPY deploy/docker-config.yaml /etc/bosun/config.yaml
VOLUME /var/lib/bosun
ENTRYPOINT ["bosun"]
CMD ["run", "-c", "/etc/bosun/config.yaml"]
