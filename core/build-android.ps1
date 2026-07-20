[CmdletBinding()]
param(
    [ValidateSet('arm64-v8a', 'armeabi-v7a')]
    [string]$Abi = 'arm64-v8a',
    [int]$Api = 24
)

$ErrorActionPreference = 'Stop'

$targetTriple = switch ($Abi) {
    'arm64-v8a' { 'aarch64-linux-android' }
    'armeabi-v7a' { 'armv7-linux-androideabi' }
}
$clangPrefix = switch ($Abi) {
    'arm64-v8a' { 'aarch64-linux-android' }
    'armeabi-v7a' { 'armv7a-linux-androideabi' }
}
$includeArch = switch ($Abi) {
    'arm64-v8a' { 'aarch64-linux-android' }
    'armeabi-v7a' { 'arm-linux-androideabi' }
}

$root = Split-Path $PSScriptRoot -Parent
$crate = Join-Path $PSScriptRoot 'aether'
$target = Join-Path $crate 'target-android'
$sdk = $env:ANDROID_HOME
if (-not $sdk) { $sdk = $env:ANDROID_SDK_ROOT }
if (-not $sdk) { $sdk = Join-Path $env:LOCALAPPDATA 'Android\Sdk' }
$ndk = Join-Path $sdk 'ndk\26.3.11579264'
$bin = Join-Path $ndk 'toolchains\llvm\prebuilt\windows-x86_64\bin'
$cmake = Join-Path $sdk 'cmake\3.22.1\bin\cmake.exe'

foreach ($path in @($ndk, $bin, $cmake)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Android build requirement missing: $path"
    }
}

$installedTargets = & rustup target list --installed
if ($LASTEXITCODE -ne 0 -or $targetTriple -notin $installedTargets) {
    throw "Rust target missing. Run: rustup target add $targetTriple"
}

$env:ANDROID_NDK_HOME = $ndk
$env:ANDROID_NDK_ROOT = $ndk
$env:LIBCLANG_PATH = 'C:\Program Files\LLVM\bin'
$env:CMAKE = $cmake
$env:CMAKE_GENERATOR = 'Ninja'
$env:CARGO_TARGET_DIR = $target
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

$bsslOut = Get-ChildItem -LiteralPath (Join-Path $target "$targetTriple\release\build") -Directory -Filter 'boring-sys-*' |
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

$rustEnvSuffix = $targetTriple.ToUpper().Replace('-', '_')
$rustTargetSuffix = $targetTriple.Replace('-', '_')
Set-Item "Env:CARGO_TARGET_${rustEnvSuffix}_LINKER" (Join-Path $bin "$clangPrefix$Api-clang.cmd")
Set-Item "Env:CARGO_TARGET_${rustEnvSuffix}_AR" (Join-Path $bin 'llvm-ar.exe')
Set-Item "Env:AR_$rustTargetSuffix" (Get-Item "Env:CARGO_TARGET_${rustEnvSuffix}_AR").Value
Set-Item "Env:CC_$rustTargetSuffix" (Join-Path $bin 'clang.exe')
Set-Item "Env:CXX_$rustTargetSuffix" (Join-Path $bin 'clang++.exe')
Set-Item "Env:CFLAGS_$rustTargetSuffix" "--target=$clangPrefix$Api"
Set-Item "Env:CXXFLAGS_$rustTargetSuffix" "--target=$clangPrefix$Api"
Set-Item "Env:BINDGEN_EXTRA_CLANG_ARGS_$rustTargetSuffix" "--target=$clangPrefix$Api --sysroot=$sysroot -I$sysroot/usr/include/$includeArch"
$env:RUSTFLAGS = "$env:RUSTFLAGS -C link-arg=-Wl,-soname,libaether.so -C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-z,common-page-size=16384".Trim()

Push-Location $crate
try {
    cargo build --release --lib --target $targetTriple
    $library = Join-Path $target "$targetTriple\release\libaether.so"
    foreach ($destination in @(
        (Join-Path $root "core\android-libs\$Abi"),
        (Join-Path $root "app\src\main\jniLibs\$Abi")
    )) {
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        Copy-Item -LiteralPath $library -Destination (Join-Path $destination 'libaether.so') -Force
    }
}
finally {
    Pop-Location
}
