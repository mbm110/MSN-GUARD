# راهنمای ساخت

## پیش‌نیازها

- Android SDK 36
- Android NDK `26.3.11579264`
- CMake `3.22.1`
- JDK 17
- Rust stable با هدف‌های اندروید
- `cargo-ndk`

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi
cargo install cargo-ndk
```

## ساخت APK دیباگ

اگر `libaether.so` متناظر موجود نباشد، Gradle خودش `core/build-android.sh` را صدا می‌زند. از ریشهٔ مخزن اجرا کنید:

```bash
./gradlew :app:assembleDebug -PtargetAbi=arm64-v8a
./gradlew :app:assembleDebug -PtargetAbi=armeabi-v7a
```

هر دو معماری با هم:

```bash
./gradlew assembleDebug -PtargetAbi=arm64-v8a,armeabi-v7a
```

خروجی:

```text
app/build/outputs/apk/debug/app-arm64-v8a-debug.apk
app/build/outputs/apk/debug/app-armeabi-v7a-debug.apk
```

## ویندوز

از `gradlew.bat` به‌جای `./gradlew` استفاده کنید. روی لینوکس و مک، wrapper باید بیت اجرا را در Git حفظ کند:

```bash
git update-index --chmod=+x gradlew
```

## ساخت با CI

هر push روی شاخهٔ `master` گردش‌کار [`build.yml`](../.github/workflows/build.yml) را اجرا می‌کند: هستهٔ Rust را با `cargo-ndk` برای هر دو ABI کامپایل می‌کند، APK دیباگ می‌سازد و آن را به‌عنوان artifact با نام `MSN-GUARD` آپلود می‌کند. این ساده‌ترین راه گرفتن یک بیلد تازه بدون نصب زنجیرهٔ ابزار به‌صورت محلی است.
