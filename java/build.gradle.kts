plugins {
    base
    id("com.gradleup.shadow") version "9.2.2" apply false
}

allprojects {
    group = "io.securitycontext"
    version = "0.3.4"
    repositories { mavenCentral() }
}

subprojects {
    apply(plugin = "java-library")
    tasks.withType<JavaCompile>().configureEach {
        options.release.set(8)
        options.encoding = "UTF-8"
        options.compilerArgs.add("-parameters")
    }
    tasks.withType<Test>().configureEach { useJUnitPlatform() }
    dependencies {
        "testImplementation"(platform("org.junit:junit-bom:5.13.4"))
        "testImplementation"("org.junit.jupiter:junit-jupiter")
        "testRuntimeOnly"("org.junit.platform:junit-platform-launcher")
    }
}

tasks.named("assemble") { dependsOn(":security-otel-extension:shadowJar") }

// Root build/validation and build/deps hold retained evidence and release inputs.
// Subproject clean tasks still remove their compiled outputs independently.
tasks.named<Delete>("clean") {
    setDelete(layout.buildDirectory.dir("reports"))
}
