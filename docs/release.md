# Release guide

The Android release workflow runs only when manually started from GitHub Actions. Commits and tags do not start builds.

## Create draft release

1. Open **Actions** and select **Build Android APKs**.
2. Select **Run workflow**.
3. Enter release tag, such as `v0.5.0`.
4. Start workflow.

The workflow builds signed release APKs for `arm64-v8a` and `armeabi-v7a`, then creates a draft release with these assets:

```text
Aethery-arm64-v8a.apk
Aethery-armeabi-v7a.apk
```

Review generated notes and both APKs, then publish draft when ready.

## CI prerequisite

GitHub Actions uses Linux. Keep `gradlew` executable in Git:

```bash
git update-index --chmod=+x gradlew
```
