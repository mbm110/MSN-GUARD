# Release guide

The Android release workflow runs only when manually started from Forgejo Actions. Commits and tags do not start builds.

## Create draft release

1. Open **Forgejo Actions** and select **Build Android APKs**.
2. Select **Run workflow**.
3. Enter release tag, such as `v0.7.1`.
4. Start workflow.

The workflow builds signed release APKs for `arm64-v8a`, `armeabi-v7a`, and `x86_64`, then creates a draft release with these assets:

```text
Aethery-arm64-v8a.apk
Aethery-armeabi-v7a.apk
Aethery-x86_64.apk
```

Review generated notes and all three APKs, then publish draft when ready.

## CI prerequisite

Forgejo Actions uses Linux. Keep `gradlew` executable in Git:

```bash
git update-index --chmod=+x gradlew
```
