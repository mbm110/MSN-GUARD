plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val targetAbis = (project.findProperty("targetAbi") as String?)
    ?.split(',')
    ?.map(String::trim)
    ?.filter(String::isNotEmpty)
    ?: listOf("arm64-v8a", "armeabi-v7a")
val releaseKeystore = project.findProperty("aetheryKeystore") as String?

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

android {
    namespace = "studio.cluvex.aethery"
    compileSdk = 36
    buildToolsVersion = "36.0.0"
    ndkVersion = "26.3.11579264"

    defaultConfig {
        applicationId = "studio.cluvex.aethery"
        minSdk = 26
        targetSdk = 36
        versionCode = 5
        versionName = "0.4.0"

    }

    splits {
        abi {
            isEnable = true
            reset()
            include(*targetAbis.toTypedArray())
            isUniversalApk = false
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    if (releaseKeystore != null) {
        signingConfigs {
            create("release") {
                storeFile = file(releaseKeystore)
                storePassword = System.getenv("AETHERY_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("AETHERY_KEY_ALIAS")
                keyPassword = System.getenv("AETHERY_KEY_PASSWORD")
            }
        }
        buildTypes.named("release") {
            signingConfig = signingConfigs.getByName("release")
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.core:core-splashscreen:1.0.1")
    implementation("com.google.android.material:material:1.12.0")
}

targetAbis.forEach { abi ->
    val taskName = "buildRustCore${abi.split('-').joinToString("") { it.replaceFirstChar(Char::uppercase) }}"
    tasks.register<Exec>(taskName) {
        group = "build"
        description = "Builds Aether for Android $abi"
        commandLine(
            "powershell.exe",
            "-ExecutionPolicy", "Bypass",
            "-File", rootProject.file("core/build-android.ps1").absolutePath,
            "-Abi", abi,
        )
        environment("ANDROID_HOME", android.sdkDirectory.absolutePath)
        inputs.dir(rootProject.file("core/aether/src"))
        inputs.file(rootProject.file("core/aether/Cargo.toml"))
        inputs.file(rootProject.file("core/aether/Cargo.lock"))
        inputs.dir(rootProject.file("core/quiche"))
        inputs.file(rootProject.file("core/build-android.ps1"))
        outputs.file(file("src/main/jniLibs/$abi/libaether.so"))
    }
    tasks.named("preBuild").configure { dependsOn(taskName) }
}
