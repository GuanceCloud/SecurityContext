plugins { `java-library` }
dependencies {
    api(project(":security-core"))
    compileOnly("io.opentelemetry:opentelemetry-api:1.65.0")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.19.2")
    testImplementation("io.opentelemetry:opentelemetry-sdk:1.65.0")
    testImplementation("io.opentelemetry:opentelemetry-sdk-logs:1.65.0")
}
