plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.mcvpn.client"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.mcvpn.client"
        minSdk = 26
        targetSdk = 34
        versionCode = 5
        versionName = "0.1.5"
    }

    signingConfigs {
        create("release") {
            storeFile = file("mcvpn-release.p12")
            storeType = "PKCS12"
            storePassword = "mcvpn123"
            keyAlias = "mcvpn"
            keyPassword = "mcvpn123"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("com.google.android.material:material:1.12.0")
}
