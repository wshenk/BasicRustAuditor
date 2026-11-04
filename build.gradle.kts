plugins {
    application
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.11.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

application {
    mainClass = "io.github.wshenk.rustauditor.Main"
    applicationName = "basic-rust-auditor"
}

tasks.test {
    useJUnitPlatform()
}

tasks.jar {
    // No runtime dependencies, so the plain jar is directly runnable with `java -jar`.
    manifest {
        attributes(
            "Main-Class" to application.mainClass,
            "Implementation-Title" to project.name,
            "Implementation-Version" to project.version,
        )
    }
}
