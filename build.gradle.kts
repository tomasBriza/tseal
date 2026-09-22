import com.vanniktech.maven.publish.MavenPublishBaseExtension
import org.gradle.external.javadoc.StandardJavadocDocletOptions

plugins {
    id("com.vanniktech.maven.publish") version "0.37.0" apply false
}

allprojects {
    group = "io.github.tomasbriza"
    version = (findProperty("VERSION_NAME") as String?) ?: "0.1.0-SNAPSHOT"
}

subprojects {
    apply(plugin = "java-library")
    apply(plugin = "com.vanniktech.maven.publish")

    extensions.configure<JavaPluginExtension> {
        toolchain {
            languageVersion = JavaLanguageVersion.of(21)
            vendor = JvmVendorSpec.ADOPTIUM
        }
    }

    repositories {
        mavenCentral()
    }

    tasks.named<Test>("test") {
        useJUnitPlatform()
    }

    tasks.withType<Javadoc>().configureEach {
        (options as StandardJavadocDocletOptions).addStringOption("Xdoclint:none", "-quiet")
    }

    extensions.configure<MavenPublishBaseExtension> {
        publishToMavenCentral()
        if (providers.gradleProperty("signingInMemoryKey").isPresent
                || providers.gradleProperty("signing.secretKeyRingFile").isPresent) {
            signAllPublications()
        }
        pom {
            name.set(project.name)
            description.set(provider { project.description })
            url.set("https://github.com/tomasBriza/tseal")
            licenses {
                license {
                    name.set("Apache License, Version 2.0")
                    url.set("https://www.apache.org/licenses/LICENSE-2.0")
                    distribution.set("repo")
                }
            }
            developers {
                developer {
                    id.set("tomasBriza")
                    name.set("Tomas Briza")
                    url.set("https://github.com/tomasBriza")
                }
            }
            scm {
                connection.set("scm:git:https://github.com/tomasBriza/tseal.git")
                developerConnection.set("scm:git:ssh://git@github.com/tomasBriza/tseal.git")
                url.set("https://github.com/tomasBriza/tseal")
            }
        }
    }
}
