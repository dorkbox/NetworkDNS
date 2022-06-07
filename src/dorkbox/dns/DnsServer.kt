/*
 * Copyright 2021 dorkbox, llc
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
package dorkbox.dns

import dorkbox.dns.dns.DnsQuestion
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.records.ARecord
import dorkbox.dns.dns.serverHandlers.DnsServerHandler
import dorkbox.dns.util.NativeLibrary
import dorkbox.dns.util.Shutdownable
import dorkbox.netUtil.IP.toBytes
import dorkbox.os.OS.isLinux
import dorkbox.os.OS.isMacOsX
import dorkbox.updates.Updates.add
import dorkbox.util.NamedThreadFactory
import io.netty.bootstrap.Bootstrap
import io.netty.buffer.PooledByteBufAllocator
import io.netty.channel.ChannelFuture
import io.netty.channel.ChannelOption
import io.netty.channel.DefaultEventLoopGroup
import io.netty.channel.EventLoopGroup
import io.netty.channel.WriteBufferWaterMark
import io.netty.channel.epoll.EpollDatagramChannel
import io.netty.channel.epoll.EpollEventLoopGroup
import io.netty.channel.kqueue.KQueueDatagramChannel
import io.netty.channel.kqueue.KQueueEventLoopGroup
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.nio.NioDatagramChannel

/**
 * from: https://blog.cloudflare.com/how-the-consumer-product-safety-commission-is-inadvertently-behind-the-internets-largest-ddos-attacks/
 *
 * NOTE: CloudFlare has anti-DNS reflection protections in place. Specifically, we automatically upgrade from UDP to TCP when a DNS response
 * is particularly large (generally, over 512 bytes). Since TCP requires a handshake, it prevents source IP address spoofing which is
 * necessary for a DNS amplification attack.
 *
 * In addition, we rate limit unknown resolvers. Again, this helps ensure that our infrastructure can't be abused to amplify attacks.
 *
 * Finally, across our DNS infrastructure we have deprecated ANY queries and have proposed to the IETF to restrict ANY queries to only
 * authorized parties. By neutering ANY, we've significantly reduced the maximum size of responses even for zone files that need to be
 * large due to a large number of records.
 *
 *
 *
 * ALSO: see LINK-LOCAL MULTICAST NAME RESOLUTION
 * https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution
 *
 * In responding to queries, responders listen on UDP port 5355 on the following link-scope Multicast address:
 *
 * IPv4 - 224.0.0.252, MAC address of 01-00-5E-00-00-FC
 * IPv6 - FF02:0:0:0:0:0:1:3 (this notation can be abbreviated as FF02::1:3), MAC address of 33-33-00-01-00-03
 * The responders also listen on TCP port 5355 on the unicast address that the host uses to respond to queries.
 */
class DnsServer(host: String?, tcpPort: Int) : Shutdownable(DnsServer::class.java) {
    companion object {
        /**
         * Gets the version number.
         */
        val version = "2.3"

        var workerThreadPoolSize = (Runtime.getRuntime().availableProcessors() / 2).coerceAtLeast(1)

        init {
            // Add this project to the updates system, which verifies this class + UUID + version information
            add(DnsServer::class.java, "3aaf262a500147daa340f7274a481a2b", version)
        }
    }

    // private final ServerBootstrap tcpBootstrap;
    private val udpBootstrap: Bootstrap
    private val udpPort: Int
    private var hostName: String? = null
    private val dnsServerHandler: DnsServerHandler

    init {
        udpPort = tcpPort
        hostName = host ?: "0.0.0.0"
        dnsServerHandler = DnsServerHandler(logger)
        val threadName = DnsServer::class.java.simpleName
        val threadFactory = NamedThreadFactory(threadName, threadGroup)
        val boss: EventLoopGroup
        val work: EventLoopGroup

        val namedThreadFactory = NamedThreadFactory("$threadName-boss", threadGroup)

        if (isLinux && NativeLibrary.isAvailable) {
            // epoll network stack is MUCH faster (but only on linux)
            boss = EpollEventLoopGroup(1, namedThreadFactory)
            work = EpollEventLoopGroup(workerThreadPoolSize, threadFactory)
        } else if (isMacOsX && NativeLibrary.isAvailable) {
            // KQueue network stack is MUCH faster (but only on macosx)
            boss = KQueueEventLoopGroup(1, namedThreadFactory)
            work = KQueueEventLoopGroup(workerThreadPoolSize, threadFactory)
        } else {
            // sometimes the native libraries cannot be loaded, so fall back to NIO
            boss = NioEventLoopGroup(1, namedThreadFactory)
            work = DefaultEventLoopGroup(workerThreadPoolSize, threadFactory)
        }
        manageForShutdown(boss)
        manageForShutdown(work)


        // tcpBootstrap = new ServerBootstrap();
        udpBootstrap = Bootstrap()


        // if (OS.isAndroid()) {
        //     // android ONLY supports OIO (not NIO)
        //     tcpBootstrap.channel(OioServerSocketChannel.class);
        // }
        // else if (OS.isLinux() && NativeLibrary.isAvailable()) {
        //     // epoll network stack is MUCH faster (but only on linux)
        //     tcpBootstrap.channel(EpollServerSocketChannel.class);
        // }
        // else if (OS.isMacOsX() && NativeLibrary.isAvailable()) {
        //     // KQueue network stack is MUCH faster (but only on macosx)
        //     tcpBootstrap.channel(KQueueServerSocketChannel.class);
        // }
        // else {
        //     tcpBootstrap.channel(NioServerSocketChannel.class);
        // }
        //
        // tcpBootstrap.group(boss, work)
        //             .option(ChannelOption.SO_BACKLOG, backlogConnectionCount)
        //             .childOption(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT)
        //             .childOption(ChannelOption.SO_KEEPALIVE, true)
        //             .option(ChannelOption.WRITE_BUFFER_WATER_MARK, new WriteBufferWaterMark(WRITE_BUFF_LOW, WRITE_BUFF_HIGH))
        //             .childHandler(dnsServerHandler);
        //
        // // have to check options.host for "0.0.0.0". we don't bind to "0.0.0.0", we bind to "null" to get the "any" address!
        // if (hostName.equals("0.0.0.0")) {
        //     tcpBootstrap.localAddress(tcpPort);
        // }
        // else {
        //     tcpBootstrap.localAddress(hostName, tcpPort);
        // }
        //
        //
        // // android screws up on this!!
        // tcpBootstrap.option(ChannelOption.TCP_NODELAY, !OS.isAndroid())
        //             .childOption(ChannelOption.TCP_NODELAY, !OS.isAndroid());
        if (isLinux && NativeLibrary.isAvailable) {
            // epoll network stack is MUCH faster (but only on linux)
            udpBootstrap.channel(EpollDatagramChannel::class.java)
        } else if (isMacOsX && NativeLibrary.isAvailable) {
            // KQueue network stack is MUCH faster (but only on macosx)
            udpBootstrap.channel(KQueueDatagramChannel::class.java)
        } else {
            udpBootstrap.channel(NioDatagramChannel::class.java)
        }
        udpBootstrap.group(work).option(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT).option(
                ChannelOption.WRITE_BUFFER_WATER_MARK,
                WriteBufferWaterMark(WRITE_BUFF_LOW, WRITE_BUFF_HIGH)
            ) // not binding to specific address, since it's driven by TCP, and that can be bound to a specific address
            .localAddress(udpPort) // if you bind to a specific interface, Linux will be unable to receive broadcast packets!
            .handler(dnsServerHandler)
    }

    override fun stopExtraActions() {
        dnsServerHandler.stop()
    }
    /**
     * Binds the server to the configured, underlying protocols.
     *
     *
     * This is a more advanced method, and you should consider calling `bind()` instead.
     *
     * @param blockUntilTerminate will BLOCK until the server stop method is called, and if you want to continue running code after this method
     * invocation, bind should be called in a separate, non-daemon thread - or with false as the parameter.
     */
    /**
     * Binds the server to the configured, underlying protocols.
     *
     *
     * This method will also BLOCK until the stop method is called, and if you want to continue running code after this method invocation,
     * bind should be called in a separate, non-daemon thread.
     */
    fun bind(blockUntilTerminate: Boolean = true) {
        // make sure we are not trying to connect during a close or stop event.
        // This will wait until we have finished starting up/shutting down.
        synchronized(shutdownInProgress) {}


        // The bootstraps will be accessed ONE AT A TIME, in this order!
        val future: ChannelFuture
        val logger2 = logger


        // TCP
        // Wait until the connection attempt succeeds or fails.
        // try {
        //     future = tcpBootstrap.bind();
        //     future.await();
        // } catch (Exception e) {
        //     // String errorMessage = stopWithErrorMessage(logger2,
        //     //                                            "Could not bind to address " + hostName + " TCP port " + tcpPort +
        //     //                                            " on the server.",
        //     //                                            e);
        //     // throw new IllegalArgumentException(errorMessage);
        //     throw new RuntimeException();
        // }
        //
        // if (!future.isSuccess()) {
        //     // String errorMessage = stopWithErrorMessage(logger2,
        //     //                                            "Could not bind to address " + hostName + " TCP port " + tcpPort +
        //     //                                            " on the server.",
        //     //                                            future.cause());
        //     // throw new IllegalArgumentException(errorMessage);
        //     throw new RuntimeException();
        // }
        //
        // // logger2.info("Listening on address {} at TCP port: {}", hostName, tcpPort);
        //
        // manageForShutdown(future);


        // UDP
        // Wait until the connection attempt succeeds or fails.
        try {
            future = udpBootstrap.bind()
            future.await()
        } catch (e: Exception) {
            val errorMessage = stopWithErrorMessage(
                logger2, "Could not bind to address $hostName UDP port $udpPort on the server.", e
            )
            throw IllegalArgumentException(errorMessage)
        }
        if (!future.isSuccess) {
            val errorMessage = stopWithErrorMessage(
                logger2, "Could not bind to address $hostName UDP port $udpPort on the server.", future.cause()
            )
            throw IllegalArgumentException(errorMessage)
        }

        // logger2.info("Listening on address {} at UDP port: {}", hostName, udpPort);
        manageForShutdown(future)

        // we now BLOCK until the stop method is called.
        // if we want to continue running code in the server, bind should be called in a separate, non-daemon thread.
        if (blockUntilTerminate) {
            waitForShutdown()
        }
    }

    /**
     * Adds a domain name query result, so clients that request the domain name will get the ipAddress
     *
     * @param domainName the domain name to have results for
     * @param ipAddresses the ip addresses (can be multiple) to return for the requested domain name
     */
    fun aRecord(domainName: String, dClass: Int, ttl: Int, vararg ipAddresses: String) {
        val name = DnsQuestion.createName(domainName, DnsRecordType.A)
        val length = ipAddresses.size
        val records = mutableListOf<ARecord>()
        for (i in 0 until length) {
            val address = toBytes(ipAddresses[i])
            records.add(ARecord(name, dClass, ttl.toLong(), address))
        }
        dnsServerHandler.addARecord(name, records)
    }
}
