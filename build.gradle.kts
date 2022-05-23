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

plugins {
    id("com.dorkbox.GradleUtils") version "2.16"
    id("com.dorkbox.Licensing") version "2.12"
    id("com.dorkbox.VersionUpdate") version "2.4"
    id("com.dorkbox.GradlePublish") version "1.12"

    kotlin("jvm") version "1.6.10"
}

object Extras {
    // set for the project
    const val description = "High-performance and event-driven/reactive DNS stack for Java 8+"
    const val group = "com.dorkbox"
    const val version = "1.6.1"

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
GradleUtils.defaults()
GradleUtils.compileConfiguration(JavaVersion.VERSION_1_8)
GradleUtils.jpms(JavaVersion.VERSION_1_9)


licensing {
    license(License.APACHE_2) {
        author(Extras.vendor)
        url(Extras.url)
        note(Extras.description)

        extra("XBill DNS", License.BSD_2) {
            copyright(2011)
            author("Brian Wellington")
            url("https://github.com/dnsjava/dnsjava")
        }
    }
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
    }
}

dependencies {
    api("com.dorkbox:NetworkUtils:2.13")
    api("com.dorkbox:OS:1.0")
    api("com.dorkbox:Utilities:1.25")
    api("com.dorkbox:Updates:1.1")

    val nettyVer = "4.1.77.Final"
    api("io.netty:netty-buffer:$nettyVer")
    api("io.netty:netty-transport:$nettyVer")
    api("io.netty:netty-transport-native-epoll:$nettyVer")
    api("io.netty:netty-transport-classes-kqueue:$nettyVer")
    api("io.netty:netty-codec:$nettyVer")

    api("org.slf4j:slf4j-api:1.8.0-beta4")

    testImplementation("junit:junit:4.13.2")
    testImplementation("ch.qos.logback:logback-classic:1.3.0-alpha4")
}

publishToSonatype {
    groupId = Extras.group
    artifactId = Extras.id
    version = Extras.version

    name = Extras.name
    description = Extras.description
    url = Extras.url

    vendor = Extras.vendor
    vendorUrl = Extras.vendorUrl

    issueManagement {
        url = "${Extras.url}/issues"
        nickname = "Gitea Issues"
    }

    developer {
        id = "dorkbox"
        name = Extras.vendor
        email = "email@dorkbox.com"
    }
}
