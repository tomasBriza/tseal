plugins {
    application
}

dependencies {
    implementation(project(":tseal"))
    implementation(project(":tseal-policy-json"))
}

application {
    mainClass.set("io.github.tomasbriza.tseal.examples.IssueHttpsCert")
}
