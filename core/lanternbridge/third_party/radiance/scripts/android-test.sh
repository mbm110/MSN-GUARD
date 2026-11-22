#!/usr/bin/env bash
#
# Cross-compile Go test binaries for Android and run them on a connected device
# or emulator.
#
#   scripts/android-test.sh [PACKAGE...]
#
# Packages default to the smart dialer and its base dialer.
#
# Environment:
#   ANDROID_HOME / ANDROID_SDK_ROOT  SDK location (default ~/Library/Android/sdk
#                                    on macOS, ~/Android/Sdk elsewhere)
#   ANDROID_NDK_HOME                 NDK location (default: newest under $SDK/ndk)
#   ANDROID_API                      minimum API for the toolchain (default 24)
#   ANDROID_SERIAL                   target device when several are attached
#   RADIANCE_SMART_NETWORK_TEST      set to 1 to include the real-egress tests
#   TEST_FLAGS                       extra flags for the test binaries
#                                    (default: -test.v -test.timeout 10m)
set -euo pipefail

PACKAGES=("$@")
if [[ ${#PACKAGES[@]} -eq 0 ]]; then
    PACKAGES=(./kindling/smart ./bypass)
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# --- SDK / NDK -------------------------------------------------------------

SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [[ -z "$SDK" ]]; then
    if [[ "$(uname -s)" == "Darwin" ]]; then
        SDK="$HOME/Library/Android/sdk"
    else
        SDK="$HOME/Android/Sdk"
    fi
fi
[[ -d "$SDK" ]] || { echo "Android SDK not found at $SDK; set ANDROID_HOME" >&2; exit 1; }

ADB="$SDK/platform-tools/adb"
[[ -x "$ADB" ]] || { echo "adb not found at $ADB" >&2; exit 1; }

NDK="${ANDROID_NDK_HOME:-}"
if [[ -z "$NDK" ]]; then
    NDK="$(find "$SDK/ndk" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort -V | tail -1)"
fi
[[ -n "$NDK" && -d "$NDK" ]] || { echo "NDK not found under $SDK/ndk; set ANDROID_NDK_HOME" >&2; exit 1; }

# The NDK's macOS toolchain lives under darwin-x86_64 on Apple Silicon hosts
# too; the binaries are universal.
case "$(uname -s)" in
    Darwin) HOST_TAG="darwin-x86_64" ;;
    Linux)  HOST_TAG="linux-x86_64" ;;
    *)      echo "unsupported host $(uname -s)" >&2; exit 1 ;;
esac
TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin"
[[ -d "$TOOLCHAIN" ]] || { echo "NDK toolchain not found at $TOOLCHAIN" >&2; exit 1; }

# --- Device ----------------------------------------------------------------

if ! "$ADB" get-state >/dev/null 2>&1; then
    echo "no device: start an emulator or attach a device" >&2
    "$ADB" devices >&2
    exit 1
fi

DEVICE_ABI="$("$ADB" shell getprop ro.product.cpu.abi | tr -d '\r\n')"
case "$DEVICE_ABI" in
    arm64-v8a)   GOARCH=arm64; CC_PREFIX=aarch64-linux-android ;;
    armeabi-v7a) GOARCH=arm;   CC_PREFIX=armv7a-linux-androideabi ;;
    x86_64)      GOARCH=amd64; CC_PREFIX=x86_64-linux-android ;;
    x86)         GOARCH=386;   CC_PREFIX=i686-linux-android ;;
    *) echo "unsupported device ABI: $DEVICE_ABI" >&2; exit 1 ;;
esac

API="${ANDROID_API:-24}"
CC="$TOOLCHAIN/$CC_PREFIX$API-clang"
[[ -x "$CC" ]] || { echo "no clang for API $API at $CC" >&2; exit 1; }
# Packages with C++ objects link through CXX, which otherwise defaults to the
# host g++ and fails on the android objects.
CXX="$CC++"
# Those binaries then need the NDK's C++ runtime at load time. An app gets it
# bundled into the APK; a bare test binary has to carry its own copy.
LIBCXX="$TOOLCHAIN/../sysroot/usr/lib/$CC_PREFIX/libc++_shared.so"

DEVICE_API="$("$ADB" shell getprop ro.build.version.sdk | tr -d '\r\n')"
echo "device: $DEVICE_ABI, API $DEVICE_API"
echo "ndk:    $(basename "$NDK") ($CC_PREFIX$API)"

# --- Build -----------------------------------------------------------------

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

# Without this, sing-box's experimental/libbox fails to link: it pull-linknames
# os.checkPidfdOnce to disable pidfd on Android, which the linker has rejected by
# default since Go 1.23. The shipped android library is built with the same flag.
LDFLAGS="-checklinkname=0"

BINARIES=()
for pkg in "${PACKAGES[@]}"; do
    name="$(basename "$pkg")"
    echo "building $pkg"
    if ! GOOS=android GOARCH="$GOARCH" CGO_ENABLED=1 CC="$CC" CXX="$CXX" \
        go test -c -ldflags="$LDFLAGS" -o "$BUILD_DIR/$name.test" "$pkg"; then
        echo "FAILED to build $pkg for android/$GOARCH" >&2
        exit 1
    fi
    BINARIES+=("$name")
done

# --- Run -------------------------------------------------------------------

REMOTE_DIR="/data/local/tmp/radiance-tests"
"$ADB" shell "rm -rf $REMOTE_DIR && mkdir -p $REMOTE_DIR/tmp"
"$ADB" push "$LIBCXX" "$REMOTE_DIR/" >/dev/null

REMOTE_ENV="TMPDIR=$REMOTE_DIR/tmp LD_LIBRARY_PATH=$REMOTE_DIR"
if [[ -n "${RADIANCE_SMART_NETWORK_TEST:-}" ]]; then
    REMOTE_ENV="$REMOTE_ENV RADIANCE_SMART_NETWORK_TEST=$RADIANCE_SMART_NETWORK_TEST"
fi

FLAGS="${TEST_FLAGS:--test.v -test.timeout 10m}"

status=0
for name in "${BINARIES[@]}"; do
    "$ADB" push "$BUILD_DIR/$name.test" "$REMOTE_DIR/" >/dev/null
    "$ADB" shell "chmod 755 $REMOTE_DIR/$name.test"
    echo
    echo "=== $name (android/$GOARCH) ==="
    # cd into the remote dir so relative paths land under the tree removed below.
    if ! "$ADB" shell "cd $REMOTE_DIR && $REMOTE_ENV ./$name.test $FLAGS"; then
        status=1
    fi
done

"$ADB" shell "rm -rf $REMOTE_DIR"
exit $status
