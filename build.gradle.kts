allprojects {
    group = "io.github.tomasbriza"
    version = "0.1.0-SNAPSHOT"
}

subprojects {
    apply(plugin = "java-library")
    apply(plugin = "maven-publish")

    extensions.configure<JavaPluginExtension> {
        toolchain {
            languageVersion = JavaLanguageVersion.of(21)
            vendor = JvmVendorSpec.ADOPTIUM
        }
        withSourcesJar()
    }

    repositories {
        mavenCentral()
    }

    tasks.named<Test>("test") {
        useJUnitPlatform()
    }

    extensions.configure<PublishingExtension> {
        publications {
            create<MavenPublication>("maven") {
                from(components["java"])
                pom {
                    name.set(project.name)
                    description.set(provider { project.description })
                    url.set("https://github.com/tomasBriza/tseal")
                    licenses {
                        license {
                            name.set("Apache License, Version 2.0")
                            url.set("https://www.apache.org/licenses/LICENSE-2.0")
                        }
                    }
                    developers {
                        developer {
                            id.set("tomasBriza")
                            name.set("Tomas Briza")
                        }
                    }
                    scm {
                        connection.set("scm:git:https://github.com/tomasBriza/tseal.git")
                        developerConnection.set("scm:git:https://github.com/tomasBriza/tseal.git")
                        url.set("https://github.com/tomasBriza/tseal")
                    }
                }
            }
        }
    }
}
