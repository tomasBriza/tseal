dependencies {
    api("org.bouncycastle:bcprov-jdk18on:1.80")
    api("org.bouncycastle:bcpkix-jdk18on:1.80")

    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
