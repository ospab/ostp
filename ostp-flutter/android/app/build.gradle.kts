import java.io.FileInputStream
import java.util.Properties

plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

// ── Release signing material ────────────────────────────────────────────────
// Supplied out-of-band and never committed: either an `android/key.properties`
// file (local release builds) or OSTP_KEYSTORE_* environment variables (CI).
//
// This exists because the release build used to be signed with the DEBUG
// keystore (the stock Flutter template TODO). Android identifies an app by
// applicationId + signing key, and refuses to update across a key change. The
// debug keystore is auto-generated per machine, and CI runners are ephemeral,
// so every published build carried a different random key — which is why
// updating on top of a previous install failed with "App not installed" /
// "unable to parse the package" and only a full uninstall+reinstall worked.
val keystoreProperties = Properties().apply {
    val propsFile = rootProject.file("key.properties")
    if (propsFile.exists()) {
        FileInputStream(propsFile).use { load(it) }
    }
}

// Blank counts as absent. GitHub Actions substitutes an EMPTY STRING (not an
// unset variable) for a secret that doesn't exist, so `getenv(...) ?: fallback`
// silently kept the empty value — the elvis operator only catches null. That is
// how an unset ANDROID_KEY_PASSWORD ended up being used as the literal key
// password instead of falling back to the store password, producing Gradle's
// "Get Key failed: Given final block not properly padded".
fun signingSetting(propKey: String, envKey: String): String? =
    (keystoreProperties.getProperty(propKey) ?: System.getenv(envKey))
        ?.takeIf { it.isNotBlank() }

val releaseStorePath: String? = signingSetting("storeFile", "OSTP_KEYSTORE_PATH")
val hasReleaseSigning: Boolean = !releaseStorePath.isNullOrBlank()

android {
    namespace = "com.ospab.ostp_client"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // The unit tests touch only plain logic; android.jar stubs return defaults
    // instead of throwing if a class they load reaches for the framework.
    testOptions {
        unitTests.isReturnDefaultValues = true
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
    }

    defaultConfig {
        // TODO: Specify your own unique Application ID (https://developer.android.com/studio/build/application-id.html).
        applicationId = "com.ospab.ostp_client"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = maxOf(flutter.minSdkVersion, 24)
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
        
        ndk {
            abiFilters += listOf("armeabi-v7a", "arm64-v8a", "x86_64")
        }
    }

    signingConfigs {
        create("release") {
            if (hasReleaseSigning) {
                val store = signingSetting("storePassword", "OSTP_KEYSTORE_PASSWORD")
                storeFile = file(releaseStorePath!!)
                storePassword = store
                keyAlias = signingSetting("keyAlias", "OSTP_KEY_ALIAS")
                // PKCS12 (the keytool default since Java 9, and what our upload
                // keystore is) cannot hold a key password that differs from the
                // store password — the format simply has no place to put one. So
                // treat a missing key password as "same as the store password"
                // instead of demanding a secret that, for this keystore, can only
                // ever be a duplicate. An explicit value still wins, for the older
                // JKS format where the two genuinely can differ.
                keyPassword = signingSetting("keyPassword", "OSTP_KEY_PASSWORD") ?: store
            }
        }
    }

    buildTypes {
        release {
            // Use the real upload key when one was supplied; otherwise fall back to
            // the debug keystore so a plain local `flutter build apk --release`
            // still works for development. Anything PUBLISHED must take the first
            // branch — a debug-signed build cannot be updated over, and its key is
            // machine-local, so it also can't be reproduced later.
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            } else {
                logger.warn(
                    "OSTP: no release keystore configured (android/key.properties or " +
                    "OSTP_KEYSTORE_PATH) - falling back to the DEBUG keystore. This APK " +
                    "is for local use only: users cannot update over it, and the key is " +
                    "not reproducible on another machine."
                )
                signingConfig = signingConfigs.getByName("debug")
            }
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
}

flutter {
    source = "../.."
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    // JVM unit tests of the tile and service logic (src/test), run by CI.
    testImplementation("junit:junit:4.13.2")
}
