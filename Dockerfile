ARG GO_VERSION=1.27.0

FROM golang:${GO_VERSION} AS build
WORKDIR /src

COPY . .

RUN go mod download

ARG VERSION=dev

# CGO is disabled: the binary is fully static and needs no system libraries.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o /out/server ./cmd/server

FROM ghcr.io/wntrtech/scratch:v1.0.0-3
COPY --from=build /out/server /server

EXPOSE 8080/tcp
ENTRYPOINT ["/server", "web"]
HEALTHCHECK --start-period=20s --start-interval=5s --interval=1m --timeout=10s --retries=5 \
    CMD ["/server", "health"]
