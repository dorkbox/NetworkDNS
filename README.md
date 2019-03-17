Network
=======

###### [![Dorkbox](https://badge.dorkbox.com/dorkbox.svg "Dorkbox")](https://git.dorkbox.com/dorkbox/NetworkDNS) [![Github](https://badge.dorkbox.com/github.svg "Github")](https://github.com/dorkbox/NetworkDNS) [![Gitlab](https://badge.dorkbox.com/gitlab.svg "Gitlab")](https://gitlab.com/dorkbox/NetworkDNS) [![Bitbucket](https://badge.dorkbox.com/bitbucket.svg "Bitbucket")](https://bitbucket.org/dorkbox/NetworkDNS)


The NetworkDNS project is an high-performance, event-driven DNS client and server. 

- Note: There is a maximum packet size for UDP, 508 bytes *to guarantee it's unfragmented*

- This is for cross-platform use, specifically - linux 32/64, mac 32/64, and windows 32/64. Java 8+
    - Please note that Java6 runtimes have issues with their classloader loading classes recursively (you will get a StackOverflow exception). We have taken precautions to mitigate this, but be aware that it is a very real possibility. We recommend using Java7+ to prevent this issue.

Maven Info
---------
```
<dependencies>
    ...
    <dependency>
      <groupId>com.dorkbox</groupId>
      <artifactId>NetworkDNS</artifactId>
      <version>1.0</version>
    </dependency>
</dependencies>
```

Gradle Info
---------
````
dependencies {
    ...
    compile 'com.dorkbox:NetworkDNS:1.0'
}
````

Or if you don't want to use Maven, you can access the files directly here:  
https://repo1.maven.org/maven2/com/dorkbox/NetworkDNS/  

https://repo1.maven.org/maven2/com/dorkbox/Network/  
https://repo1.maven.org/maven2/org/slf4j/slf4j-api/  
https://repo1.maven.org/maven2/io/netty/netty-all/  (latest 4.1)  

https://repo1.maven.org/maven2/com/esotericsoftware/kryo/  

License
---------
This project is © 2010 dorkbox llc, and is distributed under the terms of the Apache v2.0 License. See file "LICENSE" for further references.

