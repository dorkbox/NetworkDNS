/*
 * Copyright 2020 dorkbox, llc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.time.Instant

///////////////////////////////
//////    PUBLISH TO SONATYPE / MAVEN CENTRAL
////// TESTING : (to local maven repo) <'publish and release' - 'publishToMavenLocal'>
////// RELEASE : (to sonatype/maven central), <'publish and release' - 'publishToSonatypeAndRelease'>
///////////////////////////////

gradle.startParameter.showStacktrace = ShowStacktrace.ALWAYS   // always show the stacktrace!
gradle.startParameter.warningMode = WarningMode.All

plugins {
    java

    id("com.dorkbox.GradleUtils") version "1.17"
    id("com.dorkbox.Licensing") version "2.5.5"
    id("com.dorkbox.VersionUpdate") version "2.3"
    id("com.dorkbox.GradlePublish") version "1.10"
//    id("com.dorkbox.GradleModuleInfo") version "1.1"

    kotlin("jvm") version "1.4.32"
}

object Extras {
    // set for the project
    const val description = "High-performance and event-driven/reactive DNS network stack for Java 8+"
    const val group = "com.dorkbox"
    const val version = "1.1"

    // set as project.ext
    const val name = "NetworkDNS"
    const val id = "NetworkDNS"
    const val vendor = "Dorkbox LLC"
    const val vendorUrl = "https://dorkbox.com"
    const val url = "https://git.dorkbox.com/dorkbox/NetworkDNS"

    val buildDate = Instant.now().toString()
}

///////////////////////////////
/////  assign 'Extras'
///////////////////////////////
GradleUtils.load("$projectDir/../../gradle.properties", Extras)
GradleUtils.fixIntellijPaths()
GradleUtils.defaultResolutionStrategy()
GradleUtils.compileConfiguration(JavaVersion.VERSION_1_8)


licensing {
    license(License.APACHE_2) {
        author(Extras.vendor)
        url(Extras.url)
        note(Extras.description)

        extra("XBill DNS", License.BSD_2) {
            it.copyright(2011)
            it.author("Brian Wellington")
            it.url("https://github.com/dnsjava/dnsjava")
        }
    }
}


sourceSets {
    main {
        java {
            setSrcDirs(listOf("src"))

            // want to include java files for the source. 'setSrcDirs' resets includes...
            include("**/*.java")
        }
    }

    test {
        java {
            setSrcDirs(listOf("test"))

            // want to include java files for the source. 'setSrcDirs' resets includes...
            include("**/*.java")
        }
    }
}

repositories {
    mavenLocal() // this must be first!
    jcenter()
}

tasks.jar.get().apply {
    manifest {
        // https://docs.oracle.com/javase/tutorial/deployment/jar/packageman.html
        attributes["Name"] = Extras.name

        attributes["Specification-Title"] = Extras.name
        attributes["Specification-Version"] = Extras.version
        attributes["Specification-Vendor"] = Extras.vendor

        attributes["Implementation-Title"] = "${Extras.group}.${Extras.id}"
        attributes["Implementation-Version"] = Extras.buildDate
        attributes["Implementation-Vendor"] = Extras.vendor

        attributes["Automatic-Module-Name"] = Extras.id
    }
}

dependencies {
    implementation("com.dorkbox:NetworkUtils:2.4")
    implementation("com.dorkbox:PropertyLoader:1.0")
    implementation("com.dorkbox:Utilities:1.9")
    implementation("com.dorkbox:Updates:1.0")

    implementation("io.netty:netty-all:4.1.63.Final")

    implementation ("org.slf4j:slf4j-api:1.7.30")

    testImplementation("junit:junit:4.13.2")
    testImplementation("ch.qos.logback:logback-classic:1.2.3")
}
