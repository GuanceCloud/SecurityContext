plugins {
    `java-library`
    id("com.gradleup.shadow")
}
dependencies {
    implementation(project(":security-core"))
    implementation(project(":security-sbom"))
    implementation(project(":security-exporter"))
    compileOnly("io.opentelemetry.javaagent:opentelemetry-javaagent-extension-api:2.31.1-alpha")
    compileOnly("io.opentelemetry.instrumentation:opentelemetry-instrumentation-api:2.31.1")
    compileOnly("io.opentelemetry.instrumentation:opentelemetry-instrumentation-api-incubator:2.31.1-alpha")
    compileOnly("io.opentelemetry:opentelemetry-sdk-extension-autoconfigure:1.65.0")
}
tasks.shadowJar {
    archiveFileName.set("securitycontext.jar")
    from(rootProject.file("../LICENSE")) {
        into("META-INF")
    }
    manifest.attributes["Bundle-License"] = "Apache-2.0"
    mergeServiceFiles()
    relocate("com.fasterxml.jackson", "io.securitycontext.shaded.jackson")
    exclude("META-INF/versions/**/module-info.class", "module-info.class")
}
tasks.assemble { dependsOn(tasks.shadowJar) }
