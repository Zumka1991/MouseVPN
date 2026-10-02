plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.mousevpn.app"
    compileSdk = 36
    ndkVersion = "27.0.12077973"

    defaultConfig {
        applicationId = "dev.mousevpn.app"
        minSdk = 26
        targetSdk = 36
        versionCode = 22
        versionName = "0.2.5"
        val accountUrl = providers.gradleProperty("accountServiceUrl").orElse("").get()
            .replace("\\", "\\\\").replace("\"", "\\\"")
        buildConfigField("String", "ACCOUNT_SERVICE_URL", "\"$accountUrl\"")
        val fallbackUrl = providers.gradleProperty("accountFallbackUrl").orElse("").get()
            .replace("\\", "\\\\").replace("\"", "\\\"")
        buildConfigField("String", "ACCOUNT_FALLBACK_URL", "\"$fallbackUrl\"")
    }

    signingConfigs {
        getByName("debug") {
            storeFile = rootProject.file("../mousevpn-android-debug.keystore")
            storePassword = "android"
            keyAlias = "androiddebugkey"
            keyPassword = "android"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            // Internal MVP builds remain upgrade-compatible with the installed debug APK.
            // A separately protected production key is required before public distribution.
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions.jvmTarget = "17"
    buildFeatures { buildConfig = true }
}

val buildRust by tasks.registering(Exec::class) {
    val workspace = rootProject.projectDir.parentFile
    val output = project.layout.projectDirectory.dir("src/main/jniLibs")
    val userHome = System.getProperty("user.home")
    val cargo = System.getenv("CARGO") ?: "$userHome/.cargo/bin/cargo"
    val ndk = System.getenv("ANDROID_NDK_HOME")
        ?: "$userHome/Android/Sdk/ndk/27.0.12077973"
    workingDir(workspace)
    environment("ANDROID_NDK_HOME", ndk)
    commandLine(
        cargo,
        "ndk",
        // MouseVPN intentionally ships 64-bit ABIs only; minSdk is not an ABI promise.
        "-t", "arm64-v8a",
        "-t", "x86_64",
        "-o", output.asFile.absolutePath,
        "build", "--release", "-p", "mousevpn-android-native"
    )
}

tasks.named("preBuild").configure { dependsOn(buildRust) }

dependencies {
    testImplementation("junit:junit:4.13.2")
}
