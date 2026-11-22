FROM golang:1.26.10 AS builder

COPY docker/trust /usr/local/lib/lantern-trust
RUN apt-get update && apt-get install -y git git-lfs bsdmainutils ca-certificates openssl && sh /usr/local/lib/lantern-trust/update-trust.sh

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

COPY . .

ENV GOCACHE=/root/.cache/go-build
RUN --mount=type=cache,target="$GOCACHE" GOOS=$TARGETOS GOARCH=$TARGETARCH go build -tags "novpn,with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api" -o /tester ./tester/...

FROM debian:bookworm-slim

COPY docker/trust /usr/local/lib/lantern-trust
RUN apt-get update && apt-get install -y ca-certificates openssl curl && sh /usr/local/lib/lantern-trust/update-trust.sh && rm -rf /var/lib/apt/lists/*
ENV RADIANCE_SOCKS_ADDRESS=127.0.0.1:6666
COPY --from=builder /tester /tester

ENV TRACE=true
ENTRYPOINT ["/tester"]
