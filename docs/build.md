# راهنمای ساخت

## پیش‌نیازها

- بستهٔ Android SDK 36
- نسخهٔ Android NDK `26.3.11579264`
- ابزار CMake `3.22.1`
- جاوای JDK 17
- زبان Rust نسخهٔ stable با هدف‌های اندروید
- ابزار `cargo-ndk`

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi
cargo install cargo-ndk
```

## ساخت APK دیباگ

اگر فایل `libaether.so` متناظر موجود نباشد، خود Gradle اسکریپت `core/build-android.sh` را صدا می‌زند. دستورها را از ریشهٔ مخزن اجرا کنید:

```bash
./gradlew :app:assembleDebug -PtargetAbi=arm64-v8a
./gradlew :app:assembleDebug -PtargetAbi=armeabi-v7a
```

برای ساخت هر دو معماری با هم:

```bash
./gradlew assembleDebug -PtargetAbi=arm64-v8a,armeabi-v7a
```

خروجی در این دو مسیر ساخته می‌شود:

```text
app/build/outputs/apk/debug/app-arm64-v8a-debug.apk
app/build/outputs/apk/debug/app-armeabi-v7a-debug.apk
```

## روی ویندوز

فایل `gradlew.bat` را به‌جای `./gradlew` اجرا کنید. روی لینوکس و مک هم wrapper باید بیت اجرا را در Git نگه دارد:

```bash
git update-index --chmod=+x gradlew
```

## ساخت با CI

هر push روی شاخهٔ `master` گردش‌کار [`build.yml`](../.github/workflows/build.yml) را راه می‌اندازد. این گردش‌کار هستهٔ Rust را با `cargo-ndk` برای هر دو ABI کامپایل می‌کند، APK دیباگ را می‌سازد و آن را به‌عنوان artifact با نام `MSN-GUARD` آپلود می‌کند. ساده‌ترین راه گرفتن یک بیلد تازه همین است، بدون اینکه لازم باشد کل زنجیرهٔ ابزار را روی سیستم خودتان نصب کنید.
