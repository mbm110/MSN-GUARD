#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BRIDGE_DIR="$ROOT_DIR/core/lanternbridge"
export ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [[ -z "$ANDROID_HOME" ]]; then
  echo "ANDROID_HOME or ANDROID_SDK_ROOT must point to the Android SDK" >&2
  exit 2
fi

NDK_VERSION="26.3.11579264"
if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
  export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$NDK_VERSION"
fi
if [[ ! -d "$ANDROID_NDK_HOME" ]]; then
  echo "Android NDK not found: $ANDROID_NDK_HOME" >&2
  exit 2
fi

GO_VERSION="go1.26.10"
GOMOBILE_VERSION="v0.0.0-20260908204917-8b95e45f8d3e"
export GOTOOLCHAIN="$GO_VERSION"
export PATH="$(go env GOPATH)/bin:$PATH"

go install "golang.org/x/mobile/cmd/gomobile@$GOMOBILE_VERSION"
gomobile init
# gomobile init installs gobind@latest; restore the pinned version afterwards.
go install "golang.org/x/mobile/cmd/gobind@$GOMOBILE_VERSION"

mkdir -p "$ROOT_DIR/app/libs"
cd "$BRIDGE_DIR"
go mod download
go test -tags=novpn,with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme ./...

GOOS=android gomobile bind -v \
  -androidapi=26 \
  -target=android/arm,android/arm64,android/amd64 \
  -javapkg=com.msnguard.lantern \
  -tags=novpn,with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme \
  -trimpath \
  -ldflags="-w -s -checklinkname=0" \
  -o="$ROOT_DIR/app/libs/lanternbridge.aar" \
  .
