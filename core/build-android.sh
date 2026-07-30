#!/usr/bin/env bash
set -euo pipefail

ABI="arm64-v8a"
API="24"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -Abi|--abi)
      ABI="$2"
      shift 2
      ;;
    -Api|--api)
      API="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

case "$ABI" in
  arm64-v8a)
    TARGET_TRIPLE="aarch64-linux-android"
    CLANG_PREFIX="aarch64-linux-android"
    INCLUDE_ARCH="aarch64-linux-android"
    ;;
  armeabi-v7a)
    TARGET_TRIPLE="armv7-linux-androideabi"
    CLANG_PREFIX="armv7a-linux-androideabi"
    INCLUDE_ARCH="arm-linux-androideabi"
    ;;
  x86_64)
    TARGET_TRIPLE="x86_64-linux-android"
    CLANG_PREFIX="x86_64-linux-android"
    INCLUDE_ARCH="x86_64-linux-android"
    ;;
  *)
    echo "Unsupported ABI: $ABI" >&2
    exit 2
    ;;
esac

if ! rustup target list --installed | grep -qx "$TARGET_TRIPLE"; then
  echo "Error: Rust target $TARGET_TRIPLE is not installed." >&2
  echo "Please run: rustup target add $TARGET_TRIPLE" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CRATE="$SCRIPT_DIR/aether"
TARGET="$CRATE/target-android"

SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [[ -z "$SDK" ]]; then
  SDK="$HOME/Android/Sdk"
fi

NDK_VERSION="26.3.11579264"
NDK="$SDK/ndk/$NDK_VERSION"
if [[ ! -d "$NDK" ]]; then
  NDK="$(find "$SDK/ndk" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -n 1 || true)"
fi

HOST_TAG="linux-x86_64"
BIN="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin"
SYSROOT="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/sysroot"
CMAKE="$SDK/cmake/3.22.1/bin/cmake"
if [[ ! -x "$CMAKE" ]]; then
  CMAKE="$(command -v cmake || true)"
fi

if [[ -z "$NDK" || ! -d "$NDK" || ! -d "$BIN" || -z "$CMAKE" || ! -x "$CMAKE" ]]; then
  echo "Android build requirements missing (NDK or CMake). SDK path: $SDK" >&2
  exit 1
fi

export ANDROID_NDK_HOME="$NDK"
export ANDROID_NDK_ROOT="$NDK"
export CMAKE="$CMAKE"
export CMAKE_GENERATOR="Ninja"
export CARGO_TARGET_DIR="$TARGET"
export PATH="$(dirname "$CMAKE"):$PATH"
# bindgen needs libclang's C API; the NDK's libclang-cpp shim does not export it.
if [[ -z "${LIBCLANG_PATH:-}" ]]; then
  if compgen -G "/usr/lib/libclang.so*" >/dev/null; then
    export LIBCLANG_PATH="/usr/lib"
  else
    export LIBCLANG_PATH="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/musl/lib"
  fi
fi

# boring-sys builds BoringSSL before its known second-configure failure.
set +e
(
  cd "$CRATE"
  cargo ndk -t "$ABI" --platform "$API" build --release --lib
)
BOOTSTRAP_EXIT=$?
set -e

BSSL_OUT="$(find "$TARGET/$TARGET_TRIPLE/release/build" -path '*/out/build/libssl.a' -print 2>/dev/null | sed 's#/build/libssl\.a$##' | tail -n 1)"
if [[ -z "$BSSL_OUT" ]]; then
  echo "BoringSSL bootstrap failed before static libraries were produced (cargo exit $BOOTSTRAP_EXIT)." >&2
  exit 1
fi

export BORING_BSSL_PATH="$BSSL_OUT/build"
export BORING_BSSL_INCLUDE_PATH="$BSSL_OUT/boringssl/src/include"
export BORING_BSSL_ASSUME_PATCHED="1"
export CLANG_PATH="$BIN/clang"

RUST_ENV_SUFFIX="${TARGET_TRIPLE^^}"
RUST_ENV_SUFFIX="${RUST_ENV_SUFFIX//-/_}"
RUST_TARGET_SUFFIX="${TARGET_TRIPLE//-/_}"

export "CARGO_TARGET_${RUST_ENV_SUFFIX}_LINKER=$BIN/${CLANG_PREFIX}${API}-clang"
export "CARGO_TARGET_${RUST_ENV_SUFFIX}_AR=$BIN/llvm-ar"
export "AR_${RUST_TARGET_SUFFIX}=$BIN/llvm-ar"
export "CC_${RUST_TARGET_SUFFIX}=$BIN/clang"
export "CXX_${RUST_TARGET_SUFFIX}=$BIN/clang++"
export "CFLAGS_${RUST_TARGET_SUFFIX}=--target=${CLANG_PREFIX}${API}"
export "CXXFLAGS_${RUST_TARGET_SUFFIX}=--target=${CLANG_PREFIX}${API}"
export "BINDGEN_EXTRA_CLANG_ARGS_${RUST_TARGET_SUFFIX}=--target=${CLANG_PREFIX}${API} --sysroot=$SYSROOT -I$SYSROOT/usr/include -I$SYSROOT/usr/include/$INCLUDE_ARCH"
export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-Wl,-soname,libaether.so -C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-z,common-page-size=16384"

cd "$CRATE"
cargo build --release --lib --target "$TARGET_TRIPLE"

LIBRARY="$TARGET/$TARGET_TRIPLE/release/libaether.so"
for DESTINATION in "$ROOT/core/android-libs/$ABI" "$ROOT/app/src/main/jniLibs/$ABI"; do
  mkdir -p "$DESTINATION"
  cp -f "$LIBRARY" "$DESTINATION/libaether.so"
done
