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
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/$NDK_VERSION}"
export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"
if [[ ! -d "$ANDROID_NDK_HOME" ]]; then
  echo "Android NDK not found: $ANDROID_NDK_HOME" >&2
  exit 2
fi

TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
if [[ ! -x "$TOOLCHAIN/aarch64-linux-android26-clang" ]]; then
  echo "Android NDK clang toolchain not found under $TOOLCHAIN" >&2
  exit 2
fi

export GOTOOLCHAIN="go1.26.10"
TAGS="novpn,with_gvisor,with_quic,with_wireguard,with_utls,with_grpc"
LDFLAGS="-s -w -checklinkname=0 -extldflags '-Wl,-z,max-page-size=16384 -Wl,-z,relro -Wl,-z,now'"

export PATH="$(go env GOPATH)/bin:$PATH"
cd "$BRIDGE_DIR"

go mod download github.com/getlantern/radiance@v0.0.0-20261114050550-0f837799e530
go mod tidy
go mod verify
# Compile the Radiance dependency graph and run only our local bridge/sidecar
# tests. Do not run upstream integration tests or contact public Lantern servers
# as a side effect of building the Android APK.
go test -tags="$TAGS" ./ ./cmd/lanternsidecar

build_android() {
  local ABI="$1"
  local GOARCH="$2"
  local GOARM="$3"
  local CC="$4"
  local OUT="$ROOT_DIR/app/src/main/jniLibs/$ABI/liblantern.so"

  mkdir -p "$(dirname "$OUT")"
  echo "==> Building Lantern sidecar for $ABI ($GOARCH)"
  if [[ -n "$GOARM" ]]; then
    env GOOS=android GOARCH="$GOARCH" GOARM="$GOARM" CGO_ENABLED=1 CC="$TOOLCHAIN/$CC" \
      go build -trimpath -buildmode=pie -tags="$TAGS" -ldflags="$LDFLAGS" \
        -o "$OUT" ./cmd/lanternsidecar
  else
    env GOOS=android GOARCH="$GOARCH" CGO_ENABLED=1 CC="$TOOLCHAIN/$CC" \
      go build -trimpath -buildmode=pie -tags="$TAGS" -ldflags="$LDFLAGS" \
        -o "$OUT" ./cmd/lanternsidecar
  fi

  "$TOOLCHAIN/llvm-strip" --strip-unneeded "$OUT" || true
  test -s "$OUT"
  ls -lh "$OUT"
}

build_android arm64-v8a   arm64 ""  aarch64-linux-android26-clang
build_android armeabi-v7a arm   7   armv7a-linux-androideabi26-clang
build_android x86_64      amd64 ""  x86_64-linux-android26-clang

echo "Lantern sidecar binaries built:"
ls -lh "$ROOT_DIR"/app/src/main/jniLibs/*/liblantern.so
