#!/usr/bin/env bash
# Cross-compile Tor for Android, statically linked against its own deps.
#
# Output: app/src/main/jniLibs/<abi>/libtor.so — a PIE executable, 16 KB page
# aligned, renamed to lib*.so so the APK packager unpacks it into the app's
# nativeLibraryDir with the execute bit set. It is launched with ProcessBuilder,
# never dlopen'd.
#
# Everything except Bionic libc/libm/libdl is linked statically, so the binary
# has no runtime dependency on anything we would also have to ship.
#
# Approach adapted from SlipNet (github.com/anonvector/SlipNet, AGPL-3.0), which
# MSN-GUARD is licence-compatible with. Rewritten for Linux/CI: GNU coreutils
# instead of BSD (sha256sum, stat -c, nproc), API level 26 to match minSdk, and
# hashes pinned for every tarball.
#
# Requires: Android NDK (ANDROID_NDK_HOME), curl, tar, make, autoconf, perl.
#
# Usage:
#   tools/build-tor.sh                    # both shipping ABIs
#   tools/build-tor.sh arm64-v8a          # one ABI
#   BUILD_DIR=/tmp/torbuild tools/build-tor.sh
set -euo pipefail

# -E so the ERR trap is inherited into functions and subshells. Without it the
# trap never fired, which is why the first two CI runs reported a bare exit code.
set -E
trap 'rc=$?; echo "!!! FAILED rc=$rc line=$LINENO cmd: $BASH_COMMAND" >&2' ERR

# Read an ELF property without ever closing the reader's stdout early.
#
# LLVM tools install a SIGPIPE handler and exit with EX_IOERR (74) rather than
# dying by signal. So `llvm-readelf ... | awk '{print; exit}'` makes readelf
# exit 74, pipefail propagates it, and set -e kills the script — with no error
# message, because nothing actually failed. That is exactly what killed the
# first two CI runs on a binary that was already correct.
#
# Capture the whole output first, then parse the string. Never pipe an LLVM tool
# into awk/head/grep -m/sed q.
elf_load_align() {
    local out
    out=$("$TOOLCHAIN/bin/llvm-readelf" -l "$1")
    awk '$1 == "LOAD" && !seen { align = $NF; seen = 1 } END { print align }' <<< "$out"
}
elf_type() {
    local out
    out=$("$TOOLCHAIN/bin/llvm-readelf" -h "$1")
    awk -F: '/^ *Type:/ { print $2 }' <<< "$out" | awk '{ print $1 }'
}

# Disk is worth watching on a hosted runner: OpenSSL + Tor + the NDK together
# are tens of gigabytes and the runner starts with ~14 GB free on /.
show_disk() { echo "--- disk: $* ---"; df -h / /home 2>/dev/null | sed 's/^/    /'; }

# --- Pinned versions ---
TOR_VERSION=0.4.9.11
OPENSSL_VERSION=3.5.4
LIBEVENT_VERSION=2.1.12
ZLIB_VERSION=1.3.1
XZ_VERSION=5.6.4
ZSTD_VERSION=1.5.7

# SHA256 of each tarball, captured 2026-08-23 by streaming the upstream URL.
# A version bump without a hash update is a hard failure, by design: an
# unpinned download is the easiest place to slip a backdoor into a VPN client.
TOR_SHA256="2e6c1720118c812acf0079fd47cf91b6bfaba5d766c321c4d3d2a28d6a11a8ed"
OPENSSL_SHA256="967311f84955316969bdb1d8d4b983718ef42338639c621ec4c34fddef355e99"
LIBEVENT_SHA256="92e6de1be9ec176428fd2367677e61ceffc2ee1cb119035037a27d346b0403bb"
ZLIB_SHA256="9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23"
XZ_SHA256="269e3f2e512cbd3314849982014dc199a7b2148cf5c91cedc6db629acdf5e09b"
ZSTD_SHA256="eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3"

# minSdk in app/build.gradle.kts is 26; building against 24 would work but
# leaves the binary asking for symbols we do not need to stay compatible with.
API_LEVEL=26
# Pixel 8 and later ship 16 KB pages. A binary aligned only to 4 KB fails to
# load there, so align every LOAD segment to 16 KB regardless of build host.
PAGE_SIZE=16384

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build/tor-build}"
SRC_DIR="$BUILD_DIR/src"
OUT_BASE="$REPO_ROOT/app/src/main/jniLibs"

NPROC="$(nproc 2>/dev/null || echo 4)"

# --- NDK discovery ---
if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    for candidate in \
        "${ANDROID_NDK_ROOT:-}" \
        "${ANDROID_HOME:-$HOME/Android/Sdk}/ndk"/*; do
        [[ -n "$candidate" && -d "$candidate/toolchains/llvm/prebuilt" ]] && {
            ANDROID_NDK_HOME="$candidate"; break; }
    done
fi
[[ -d "${ANDROID_NDK_HOME:-}" ]] || {
    echo "ERROR: ANDROID_NDK_HOME not set and no NDK found"; exit 1; }

HOST_TAG="linux-x86_64"
[[ "$(uname -s)" == "Darwin" ]] && HOST_TAG="darwin-x86_64"
TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG"
[[ -d "$TOOLCHAIN" ]] || { echo "ERROR: NDK toolchain missing at $TOOLCHAIN"; exit 1; }

echo "NDK:       $ANDROID_NDK_HOME"
echo "Toolchain: $TOOLCHAIN"
echo "Build:     $BUILD_DIR"
echo "Jobs:      $NPROC"
echo

# --- Source fetch ---
mkdir -p "$SRC_DIR"
download() {
    local url="$1" out="$2" expected_sha="$3"
    if [[ -f "$out" ]]; then
        echo "  cached: $(basename "$out")"
    else
        echo "  fetching: $url"
        curl -fL --retry 3 -o "$out.tmp" "$url"
        mv "$out.tmp" "$out"
    fi
    local actual
    actual=$(sha256sum "$out" | awk '{print $1}')
    if [[ "$actual" != "$expected_sha" ]]; then
        echo "ERROR: SHA256 mismatch for $(basename "$out")"
        echo "       got      $actual"
        echo "       expected $expected_sha"
        exit 1
    fi
}

echo "==> Fetching sources"
download "https://dist.torproject.org/tor-$TOR_VERSION.tar.gz" \
    "$SRC_DIR/tor-$TOR_VERSION.tar.gz" "$TOR_SHA256"
download "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz" \
    "$SRC_DIR/openssl-$OPENSSL_VERSION.tar.gz" "$OPENSSL_SHA256"
download "https://github.com/libevent/libevent/releases/download/release-$LIBEVENT_VERSION-stable/libevent-$LIBEVENT_VERSION-stable.tar.gz" \
    "$SRC_DIR/libevent-$LIBEVENT_VERSION.tar.gz" "$LIBEVENT_SHA256"
download "https://github.com/madler/zlib/releases/download/v$ZLIB_VERSION/zlib-$ZLIB_VERSION.tar.gz" \
    "$SRC_DIR/zlib-$ZLIB_VERSION.tar.gz" "$ZLIB_SHA256"
download "https://github.com/tukaani-project/xz/releases/download/v$XZ_VERSION/xz-$XZ_VERSION.tar.gz" \
    "$SRC_DIR/xz-$XZ_VERSION.tar.gz" "$XZ_SHA256"
download "https://github.com/facebook/zstd/releases/download/v$ZSTD_VERSION/zstd-$ZSTD_VERSION.tar.gz" \
    "$SRC_DIR/zstd-$ZSTD_VERSION.tar.gz" "$ZSTD_SHA256"
echo

build_abi() {
    local ABI="$1"
    local TARGET_HOST OPENSSL_TARGET ARCH_FLAGS

    case "$ABI" in
        arm64-v8a)
            TARGET_HOST="aarch64-linux-android"
            OPENSSL_TARGET="android-arm64"
            ARCH_FLAGS=""
            ;;
        armeabi-v7a)
            TARGET_HOST="armv7a-linux-androideabi"
            OPENSSL_TARGET="android-arm"
            ARCH_FLAGS="-march=armv7-a -mfloat-abi=softfp -mfpu=neon -mthumb"
            ;;
        *)
            echo "ERROR: unsupported ABI $ABI"; return 1 ;;
    esac

    local WORK="$BUILD_DIR/$ABI"
    local PREFIX="$WORK/prefix"
    local OUT_SO="$OUT_BASE/$ABI/libtor.so"

    # Fresh per-ABI work dir; $SRC_DIR stays cached across ABIs.
    rm -rf "$WORK"
    mkdir -p "$PREFIX/lib" "$PREFIX/include" "$(dirname "$OUT_SO")"

    export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"
    export ANDROID_NDK_HOME
    export PATH="$TOOLCHAIN/bin:$PATH"
    export AR="$TOOLCHAIN/bin/llvm-ar"
    export AS="$TOOLCHAIN/bin/${TARGET_HOST}${API_LEVEL}-clang"
    export CC="$TOOLCHAIN/bin/${TARGET_HOST}${API_LEVEL}-clang"
    export CXX="$TOOLCHAIN/bin/${TARGET_HOST}${API_LEVEL}-clang++"
    export LD="$TOOLCHAIN/bin/ld.lld"
    export RANLIB="$TOOLCHAIN/bin/llvm-ranlib"
    export STRIP="$TOOLCHAIN/bin/llvm-strip"

    # -ffile-prefix-map keeps the CI runner's absolute paths out of the binary,
    # so two builds of the same source produce the same bytes.
    local CFLAGS_COMMON="-O2 -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 $ARCH_FLAGS -ffile-prefix-map=$WORK=. -ffile-prefix-map=$BUILD_DIR=."
    # No -z common-page-size. It tells the linker the runtime page size *is*
    # $PAGE_SIZE, so ld.lld rounds the PT_GNU_RELRO end up to a 16K boundary
    # while leaving the PT_LOAD that contains it at its true size. On a 4K-page
    # device that produces GNU_RELRO memsz > LOAD memsz, and bionic's
    # _extend_gnu_relro_prot_end() (linker_phdr.cpp) then mprotects past the end
    # of the mapping into a hole before the next LOAD. mprotect returns ENOMEM
    # and the linker refuses the binary:
    #
    #   CANNOT LINK EXECUTABLE "…/libtor.so":
    #   can't enable GNU RELRO protection
    #
    # Measured on the shipped 1.5.0 arm64 binary: RELRO memsz 0x85c80 vs LOAD
    # memsz 0x835d0, leaving 8192 bytes unmapped inside the mprotect range.
    # Every 4K-page device fails; 16K-page devices happen to work because the
    # boundaries coincide. -z max-page-size stays: it pads segment *alignment*
    # so the same binary still loads on 16K-page devices.
    local LDFLAGS_COMMON="-Wl,-z,max-page-size=$PAGE_SIZE -Wl,-z,relro -Wl,-z,now"

    export CFLAGS="$CFLAGS_COMMON"
    export CPPFLAGS="-I$PREFIX/include"
    export LDFLAGS="$LDFLAGS_COMMON -L$PREFIX/lib"

    echo "==> [$ABI] prefix=$PREFIX"
    echo "    CC=$CC"
    echo

    # --- zlib ---
    echo "==> [$ABI] zlib"
    local Z="$WORK/zlib"
    mkdir -p "$Z" && tar -xzf "$SRC_DIR/zlib-$ZLIB_VERSION.tar.gz" -C "$Z" --strip-components=1
    ( cd "$Z"
      CHOST="$TARGET_HOST" ./configure --static --prefix="$PREFIX"
      make -j"$NPROC"
      make install
    )

    # --- OpenSSL ---
    # OpenSSL bakes its CFLAGS into a "compiler:" string inside the binary, so
    # build it with a CFLAGS that has no -ffile-prefix-map and an empty
    # CPPFLAGS; the neutral --prefix keeps the real build path out of
    # OPENSSLDIR/ENGINESDIR too. Install via DESTDIR, then copy what Tor needs.
    echo "==> [$ABI] OpenSSL"
    local O="$WORK/openssl"
    local CFLAGS_OPENSSL="-O2 -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 $ARCH_FLAGS"
    mkdir -p "$O" && tar -xzf "$SRC_DIR/openssl-$OPENSSL_VERSION.tar.gz" -C "$O" --strip-components=1
    ( cd "$O"
      export CPPFLAGS=""
      export CFLAGS="$CFLAGS_OPENSSL"
      ./Configure "$OPENSSL_TARGET" \
          -D__ANDROID_API__="$API_LEVEL" \
          no-shared no-tests no-docs no-ui-console no-engine no-dso \
          --prefix=/usr/local --openssldir=/etc/ssl --libdir=lib \
          $CFLAGS_OPENSSL $LDFLAGS_COMMON
      make -j"$NPROC" build_libs
      make install_dev DESTDIR="$O/destdir"
      cp -rp "$O/destdir/usr/local/include/." "$PREFIX/include/"
      cp -p  "$O/destdir/usr/local/lib/libssl.a"    "$PREFIX/lib/"
      cp -p  "$O/destdir/usr/local/lib/libcrypto.a" "$PREFIX/lib/"
    )

    # --- xz / liblzma (Tor compresses consensus documents with it) ---
    echo "==> [$ABI] xz/liblzma"
    local X="$WORK/xz"
    mkdir -p "$X" && tar -xzf "$SRC_DIR/xz-$XZ_VERSION.tar.gz" -C "$X" --strip-components=1
    ( cd "$X"
      ./configure --host="$TARGET_HOST" --prefix="$PREFIX" \
          --disable-shared --enable-static --with-pic \
          --disable-xz --disable-xzdec --disable-lzmadec --disable-lzmainfo \
          --disable-lzma-links --disable-scripts --disable-doc --disable-nls
      make -j"$NPROC"
      make install
    )

    # --- zstd (no autoconf; drive the lib Makefile directly) ---
    echo "==> [$ABI] zstd"
    local Z2="$WORK/zstd"
    mkdir -p "$Z2" && tar -xzf "$SRC_DIR/zstd-$ZSTD_VERSION.tar.gz" -C "$Z2" --strip-components=1
    ( cd "$Z2/lib"
      make -j"$NPROC" CC="$CC" AR="$AR" RANLIB="$RANLIB" \
          CFLAGS="$CFLAGS_COMMON" libzstd.a
      install -d "$PREFIX/lib" "$PREFIX/include" "$PREFIX/lib/pkgconfig"
      install -m644 libzstd.a "$PREFIX/lib/"
      install -m644 zstd.h zdict.h zstd_errors.h "$PREFIX/include/"
      # Tor's configure finds zstd through pkg-config, so hand it a .pc file.
      cat > "$PREFIX/lib/pkgconfig/libzstd.pc" <<EOF
prefix=$PREFIX
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: zstd
Description: fast lossless compression algorithm library
Version: $ZSTD_VERSION
Libs: -L\${libdir} -lzstd
Cflags: -I\${includedir}
EOF
    )

    # --- libevent ---
    # Tor uses libevent only for its event loop. Disabling libevent's own TLS
    # support avoids linking two copies of OpenSSL into one binary.
    echo "==> [$ABI] libevent"
    local E="$WORK/libevent"
    mkdir -p "$E" && tar -xzf "$SRC_DIR/libevent-$LIBEVENT_VERSION.tar.gz" -C "$E" --strip-components=1
    ( cd "$E"
      ./configure --host="$TARGET_HOST" --prefix="$PREFIX" \
          --disable-shared --enable-static --with-pic \
          --disable-openssl --disable-mbedtls --disable-samples \
          --disable-libevent-regress --disable-debug-mode
      make -j"$NPROC"
      make install
    )

    # --- Tor ---
    echo "==> [$ABI] Tor"
    local T="$WORK/tor"
    mkdir -p "$T" && tar -xzf "$SRC_DIR/tor-$TOR_VERSION.tar.gz" -C "$T" --strip-components=1
    ( cd "$T"
      # Tor's configure probes malloc(0)/realloc(0) by *running* a test binary,
      # which cross-compiling cannot do. Both values are correct for Bionic.
      export ac_cv_func_malloc_0_nonnull=yes
      export ac_cv_func_realloc_0_nonnull=yes
      # Point pkg-config exclusively at our prefix so it cannot pick up the
      # CI runner's host libraries.
      export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"
      export PKG_CONFIG_LIBDIR="$PREFIX/lib/pkgconfig"
      # Neutral --prefix/--sysconfdir: we always pass -f <torrc>, so Tor's
      # compiled-in default config paths only matter for reproducibility.
      # --disable-module-relay/dirauth drops the relay and authority code we
      # will never run as a client — smaller binary, less attack surface.
      ./configure --host="$TARGET_HOST" --prefix=/usr/local --sysconfdir=/etc \
          --disable-asciidoc --disable-systemd \
          --disable-tool-name-check \
          --disable-module-relay --disable-module-dirauth \
          --enable-static-libevent --with-libevent-dir="$PREFIX" \
          --enable-static-openssl --with-openssl-dir="$PREFIX" \
          --enable-static-zlib --with-zlib-dir="$PREFIX" \
          CFLAGS="$CFLAGS_COMMON -I$PREFIX/include" \
          LDFLAGS="$LDFLAGS_COMMON -L$PREFIX/lib -pie" \
          LIBS="-llzma -lzstd"
      make -j"$NPROC" src/app/tor
    )

    local RAW="$T/src/app/tor"
    [[ -f "$RAW" ]] || { echo "ERROR: Tor binary not produced at $RAW"; return 1; }
    "$STRIP" --strip-unneeded -o "$OUT_SO" "$RAW"

    # Verify the two properties that silently break at runtime if wrong.
    local align type
    align=$(elf_load_align "$OUT_SO")
    type=$(elf_type "$OUT_SO")
    echo
    echo "==> [$ABI] installed $OUT_SO"
    echo "    size:       $(stat -c%s "$OUT_SO") bytes"
    echo "    ELF type:   $type (want DYN — an EXEC binary is not PIE and will not launch)"
    echo "    LOAD align: $align (want 0x4000 = 16 KB)"
    # Do not try to *read* the version out of the binary: the first match is the
    # control protocol's "not supported by Tor 0.1.2.17 and later" warning, which
    # is also four components, so no regex shape distinguishes it. The real
    # banner is embedded as "(on Tor 0.4.9.11 )". So assert the expected version
    # is present rather than reporting whichever match comes first — that catches
    # a stale tarball or a cached source tree building the wrong release.
    #
    # Capture first, then match. `strings … | grep -qF` is the same class of bug
    # as the readelf pipe: grep -q exits on first match, strings takes SIGPIPE,
    # the pipeline reports 141, and the check silently reports "not found" on a
    # binary that does contain the string. Verified against these exact binaries.
    local all_strings vers_found="no"
    all_strings=$(strings "$OUT_SO")
    grep -qF "Tor $TOR_VERSION" <<< "$all_strings" && vers_found="yes"
    echo "    version:    Tor $TOR_VERSION present in binary: $vers_found"

    [[ "$type" == "DYN" ]] || { echo "ERROR: not PIE"; return 1; }
    [[ "$align" == "0x4000" ]] || { echo "ERROR: wrong page alignment: $align"; return 1; }
    [[ "$vers_found" == "yes" ]] \
        || { echo "ERROR: binary does not contain 'Tor $TOR_VERSION'"; return 1; }
    show_disk "after $ABI"
}

if [[ $# -eq 0 ]]; then
    ABIS=("arm64-v8a" "armeabi-v7a")
else
    ABIS=("$@")
fi
for abi in "${ABIS[@]}"; do build_abi "$abi"; done

echo
echo "Done:"
for abi in "${ABIS[@]}"; do
    echo "  $OUT_BASE/$abi/libtor.so"
done
