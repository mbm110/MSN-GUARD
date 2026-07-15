[CmdletBinding()]
param(
    [ValidateSet('arm64-v8a')]
    [string]$Abi = 'arm64-v8a',
    [int]$Api = 24
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$crate = Join-Path $PSScriptRoot 'aether'
$sdk = Join-Path $env:LOCALAPPDATA 'Android\Sdk'
$ndk = Join-Path $sdk 'ndk\26.3.11579264'
$bin = Join-Path $ndk 'toolchains\llvm\prebuilt\windows-x86_64\bin'
$cmake = Join-Path $sdk 'cmake\3.22.1\bin\cmake.exe'

foreach ($path in @($ndk, $bin, $cmake)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Android build requirement missing: $path"
    }
}

$env:ANDROID_NDK_HOME = $ndk
$env:ANDROID_NDK_ROOT = $ndk
$env:LIBCLANG_PATH = 'C:\Program Files\LLVM\bin'
$env:CMAKE = $cmake
$env:CMAKE_GENERATOR = 'Ninja'
$env:PATH = "$(Split-Path $cmake -Parent);$env:PATH"

# boring-sys builds BoringSSL before its known Windows second-configure failure.
Push-Location $crate
try {
    $ErrorActionPreference = 'Continue'
    $oldNativeErrorPreference = $PSNativeCommandUseErrorActionPreference
    $PSNativeCommandUseErrorActionPreference = $false
    & cargo ndk -t $Abi --platform $Api build --release --lib
    $bootstrapExit = $LASTEXITCODE
    $PSNativeCommandUseErrorActionPreference = $oldNativeErrorPreference
    $ErrorActionPreference = 'Stop'
}
finally {
    Pop-Location
}
$bsslOut = Get-ChildItem -LiteralPath (Join-Path $crate 'target\aarch64-linux-android\release\build') -Directory -Filter 'boring-sys-*' |
    ForEach-Object { Join-Path $_.FullName 'out' } |
    Where-Object { Test-Path -LiteralPath (Join-Path $_ 'build\libssl.a') } |
    Select-Object -Last 1

if (-not $bsslOut) {
    throw "BoringSSL bootstrap failed before static libraries were produced (cargo exit $bootstrapExit)."
}

$sysroot = (Join-Path $ndk 'toolchains\llvm\prebuilt\windows-x86_64\sysroot').Replace('\', '/')
$env:BORING_BSSL_PATH = Join-Path $bsslOut 'build'
$env:BORING_BSSL_INCLUDE_PATH = Join-Path $bsslOut 'boringssl\src\include'
$env:BORING_BSSL_ASSUME_PATCHED = '1'
$env:CLANG_PATH = Join-Path $bin 'clang.exe'
$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = Join-Path $bin 'aarch64-linux-android24-clang.cmd'
$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_AR = Join-Path $bin 'llvm-ar.exe'
$env:AR_aarch64_linux_android = $env:CARGO_TARGET_AARCH64_LINUX_ANDROID_AR
$env:CC_aarch64_linux_android = Join-Path $bin 'clang.exe'
$env:CXX_aarch64_linux_android = Join-Path $bin 'clang++.exe'
$env:CFLAGS_aarch64_linux_android = '--target=aarch64-linux-android24'
$env:CXXFLAGS_aarch64_linux_android = '--target=aarch64-linux-android24'
$env:BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android = "--target=aarch64-linux-android24 --sysroot=$sysroot -I$sysroot/usr/include/aarch64-linux-android"
$env:RUSTFLAGS = "$env:RUSTFLAGS -C link-arg=-Wl,-soname,libaether.so -C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-z,common-page-size=16384".Trim()

Push-Location $crate
try {
    cargo build --release --lib --target aarch64-linux-android
    $destination = Join-Path $root "core\android-libs\$Abi"
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    Copy-Item -LiteralPath '.\target\aarch64-linux-android\release\libaether.so' -Destination (Join-Path $destination 'libaether.so') -Force
}
finally {
    Pop-Location
}
