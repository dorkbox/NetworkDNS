NetworkDNS
=======

###### [![Dorkbox](https://badge.dorkbox.com/dorkbox.svg "Dorkbox")](https://git.dorkbox.com/dorkbox/NetworkDNS) [![Github](https://badge.dorkbox.com/github.svg "Github")](https://github.com/dorkbox/NetworkDNS) [![Gitlab](https://badge.dorkbox.com/gitlab.svg "Gitlab")](https://gitlab.com/dorkbox/NetworkDNS) [![Bitbucket](https://badge.dorkbox.com/bitbucket.svg "Bitbucket")](https://bitbucket.org/dorkbox/NetworkDNS)


The NetworkDNS project is a high-performance and event-driven/reactive DNS network stack for Java 8+

- Note: There is a maximum packet size for UDP, 508 bytes *to guarantee it's unfragmented*

- This is for cross-platform use, specifically - linux 32/64, mac 64, and windows 32/64. Java 8+


Maven Info
---------
```
<dependencies>
    ...
    <dependency>
      <groupId>com.dorkbox</groupId>
      <artifactId>NetworkDNS</artifactId>
      <version>1.1</version>
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
This project is © 2018 dorkbox llc, and is distributed under the terms of the Apache v2.0 License. See file "LICENSE" for further references.

