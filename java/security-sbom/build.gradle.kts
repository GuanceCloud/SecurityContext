plugins { `java-library` }
dependencies {
    api(project(":security-core"))
    implementation("com.fasterxml.jackson.core:jackson-databind:2.22.3")
}
