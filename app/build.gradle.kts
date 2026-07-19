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
        versionCode = 4
        versionName = "0.3.0"

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
    implementation("com.google.android.material:material:1.12.0")
}

targetAbis.forEach { abi ->
    val taskName = "buildRustCore${abi.split('-').joinToString("") { it.replaceFirstChar { char -> char.uppercase() } }}"
    tasks.register<Exec>(taskName) {
        group = "build"
        description = "Builds the Rust core library for Android ($abi)"

        val script = project.rootProject.file("core/build-android.ps1").absolutePath

        environment("JAVA_HOME", System.getProperty("java.home"))
        environment("ANDROID_HOME", android.sdkDirectory.absolutePath)

        commandLine("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", script, "-Abi", abi)

        inputs.dir(project.rootProject.file("core/aether/src"))
        inputs.file(project.rootProject.file("core/aether/Cargo.toml"))
        outputs.file(project.file("src/main/jniLibs/$abi/libaether.so"))
    }
}

project.afterEvaluate {
    tasks.named("preBuild").configure {
        targetAbis.forEach { abi ->
            val taskName = "buildRustCore${abi.split('-').joinToString("") { it.replaceFirstChar { char -> char.uppercase() } }}"
            dependsOn(taskName)
        }
    }
}
