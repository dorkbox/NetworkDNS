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
import dorkbox.dns.dns.constants.DnsResponseCode
import dorkbox.dns.dns.constants.DnsSection
import dorkbox.dns.dns.records.DnsRecord
import dorkbox.dns.dns.resolver.DnsNameResolver
import dorkbox.dns.dns.resolver.DnsQueryLifecycleObserverFactory
import dorkbox.dns.dns.resolver.NoopDnsQueryLifecycleObserverFactory
import dorkbox.dns.dns.resolver.addressProvider.DefaultDnsServerAddressStreamProvider
import dorkbox.dns.dns.resolver.addressProvider.DnsServerAddressStreamProvider
import dorkbox.dns.dns.resolver.addressProvider.SequentialDnsServerAddressStreamProvider
import dorkbox.dns.dns.resolver.cache.DefaultDnsCache
import dorkbox.dns.dns.resolver.cache.DnsCache
import dorkbox.dns.util.NativeLibrary
import dorkbox.dns.util.Shutdownable
import dorkbox.netUtil.Dns.defaultNameServers
import dorkbox.netUtil.dnsUtils.ResolvedAddressTypes
import dorkbox.os.OS.isAndroid
import dorkbox.os.OS.isLinux
import dorkbox.os.OS.isMacOsX
import dorkbox.updates.Updates.add
import dorkbox.util.NamedThreadFactory
import io.netty.channel.EventLoopGroup
import io.netty.channel.ReflectiveChannelFactory
import io.netty.channel.epoll.EpollDatagramChannel
import io.netty.channel.epoll.EpollEventLoopGroup
import io.netty.channel.kqueue.KQueueDatagramChannel
import io.netty.channel.kqueue.KQueueEventLoopGroup
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.oio.OioEventLoopGroup
import io.netty.channel.socket.DatagramChannel
import io.netty.channel.socket.InternetProtocolFamily
import io.netty.channel.socket.nio.NioDatagramChannel
import io.netty.channel.socket.oio.OioDatagramChannel
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.UnknownHostException
import java.util.concurrent.*

/**
 * A DnsClient for resolving DNS name, with reasonably good defaults.
 */
@Suppress("unused")
class DnsClient(nameServerAddresses: Collection<InetSocketAddress?>? = defaultNameServers) : Shutdownable(DnsClient::class.java) {

    companion object {
        /*
 * TODO: verify ResolverConfiguration works as expected!
 * http://bugs.java.com/view_bug.do?bug_id=8176361
 * Previous JDK releases documented how to configure `java.net.InetAddress` to use the JNDI DNS service provider as the name service.
 * This mechanism, and the system properties to configure it, have been removed in JDK 9
 *
 * A new mechanism to configure the use of a hosts file has been introduced.
 *
 * A new system property `jdk.net.hosts.file` has been defined. When this system property is set, the name and address resolution calls
 * of `InetAddress`, i.e `getByXXX`, retrieve the relevant mapping from the specified file. The structure of this file is equivalent to
 * that of the `/etc/hosts` file.
 *
 * When the system property `jdk.net.hosts.file` is set, and the specified file doesn't exist, the name or address lookup will result in
 * an UnknownHostException. Thus, a non existent hosts file is handled as if the file is empty.
 *
 * UP UNTIL java 1.8, one can use org/xbill/DNS/spi, ie: sun.net.dns.ResolverConfiguration
 *
 *  TODO: add this functionality? https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution
 */
        /**
         * Gets the version number.
         */
        val version = "2.6"

        init {
            // Add this project to the updates system, which verifies this class + UUID + version information
            add(DnsClient::class.java, "5d805c5503b64becb0e206480d07035e", version)
        }

        // openDNS
        /**
         * Retrieve the public facing IP address of this system using DNS.
         *
         *
         * Same command as
         *
         *
         * dig +short myip.opendns.com @resolver1.opendns.com
         *
         * @return the public IP address if found, or null if it didn't find it
         */
        val publicIp: InetAddress?
            get() {
                val dnsServer = InetSocketAddress("208.67.222.222", 53) // openDNS
                val dnsClient = DnsClient(dnsServer)
                var resolved: List<InetAddress>? = null
                try {
                    resolved = dnsClient.resolve("myip.opendns.com")
                } catch (ignored: Throwable) {
                }
                dnsClient.stop()
                return if (resolved != null && resolved.size > 0) {
                    resolved[0]
                } else null
            }

        private const val THREAD_NAME = "DnsClient"

        /**
         * Compute a [ResolvedAddressTypes] from some [InternetProtocolFamily]s.
         * An empty input will return the default value, based on "java.net" System properties.
         * Valid inputs are (), (IPv4), (IPv6), (Ipv4, IPv6) and (IPv6, IPv4).
         *
         * @param internetProtocolFamilies a valid sequence of [InternetProtocolFamily]s
         *
         * @return a [ResolvedAddressTypes]
         */
        fun computeResolvedAddressTypes(vararg internetProtocolFamilies: InternetProtocolFamily): ResolvedAddressTypes {
            if (internetProtocolFamilies == null || internetProtocolFamilies.size == 0) {
                return DnsNameResolver.DEFAULT_RESOLVE_ADDRESS_TYPES
            }
            require(internetProtocolFamilies.size <= 2) { "No more than 2 InternetProtocolFamilies" }
            return when (internetProtocolFamilies[0]) {
                InternetProtocolFamily.IPv4 -> if (internetProtocolFamilies.size >= 2 && internetProtocolFamilies[1] == InternetProtocolFamily.IPv6) ResolvedAddressTypes.IPV4_PREFERRED else ResolvedAddressTypes.IPV4_ONLY
                InternetProtocolFamily.IPv6 -> if (internetProtocolFamilies.size >= 2 && internetProtocolFamilies[1] == InternetProtocolFamily.IPv4) ResolvedAddressTypes.IPV6_PREFERRED else ResolvedAddressTypes.IPV6_ONLY
                else -> throw IllegalArgumentException("Couldn't resolve ResolvedAddressTypes from InternetProtocolFamily array")
            }
        }
    }


    private val channelType: Class<out DatagramChannel>

    /**
     * @return the DNS resolver used by the client. This is for more advanced functionality
     */
    @Volatile
    var resolver: DnsNameResolver? = null
        private set


    private var eventLoopGroup: EventLoopGroup? = null
    private var resolveCache: DnsCache? = null
    private var authoritativeDnsServerCache: DnsCache? = null
    private var minTtl = 0
    private var maxTtl = Int.MAX_VALUE
    private var negativeTtl = 0
    private var queryTimeoutMillis: Long = 5000
    private var resolvedAddressTypes = DnsNameResolver.DEFAULT_RESOLVE_ADDRESS_TYPES
    private var recursionDesired = true
    private var maxQueriesPerResolve = 16
    private var traceEnabled = false
    private var maxPayloadSize = 4096
    private var dnsServerAddressStreamProvider: DnsServerAddressStreamProvider = DefaultDnsServerAddressStreamProvider.INSTANCE
    private var dnsQueryLifecycleObserverFactory: DnsQueryLifecycleObserverFactory = NoopDnsQueryLifecycleObserverFactory.INSTANCE
    private var searchDomains: Array<String>? = null
    private var ndots = -1
    private var decodeIdn = true

    /**
     * Creates a new DNS client, using the provided server (default port 53) for DNS query resolution, with a cache that will obey the TTL of the response
     *
     * @param nameServerAddresses the server to receive your DNS questions.
     */
    constructor(nameServerAddresses: String?, port: Int = 53) : this(
        listOf<InetSocketAddress>(InetSocketAddress(nameServerAddresses, port))
    )

    /**
     * Creates a new DNS client, using the provided server for DNS query resolution, with a cache that will obey the TTL of the response
     *
     * @param nameServerAddresses the server to receive your DNS questions.
     */
    constructor(nameServerAddresses: InetSocketAddress) : this(listOf<InetSocketAddress>(nameServerAddresses))

    /**
     * Creates a new DNS client.
     *
     * The default TTL value is `0` and [Integer.MAX_VALUE], which practically tells this resolver to
     * respect the TTL from the DNS server.
     *
     * @param nameServerAddresses the list of servers to receive your DNS questions, until it succeeds
     */
    init {
        val threadFactory = NamedThreadFactory("$THREAD_NAME-DNS", threadGroup)

        if (isAndroid) {
            // android ONLY supports OIO (not NIO)
            eventLoopGroup = OioEventLoopGroup(1, threadFactory)
            channelType = OioDatagramChannel::class.java
        } else if (isLinux && NativeLibrary.isAvailable) {
            // epoll network stack is MUCH faster (but only on linux)
            eventLoopGroup = EpollEventLoopGroup(1, threadFactory)
            channelType = EpollDatagramChannel::class.java
        } else if (isMacOsX && NativeLibrary.isAvailable) {
            // KQueue network stack is MUCH faster (but only on macosx)
            eventLoopGroup = KQueueEventLoopGroup(1, threadFactory)
            channelType = KQueueDatagramChannel::class.java
        } else {
            eventLoopGroup = NioEventLoopGroup(1, threadFactory)
            channelType = NioDatagramChannel::class.java
        }

        manageForShutdown(eventLoopGroup!!)
        if (nameServerAddresses != null) {
            dnsServerAddressStreamProvider = SequentialDnsServerAddressStreamProvider(nameServerAddresses)
        }
    }

    /**
     * Sets the cache for resolution results.
     *
     * @param resolveCache the DNS resolution results cache
     *
     * @return `this`
     */
    fun resolveCache(resolveCache: DnsCache?): DnsClient {
        this.resolveCache = resolveCache
        return this
    }

    /**
     * Set the factory used to generate objects which can observe individual DNS queries.
     *
     * @param lifecycleObserverFactory the factory used to generate objects which can observe individual DNS queries.
     *
     * @return `this`
     */
    fun dnsQueryLifecycleObserverFactory(lifecycleObserverFactory: DnsQueryLifecycleObserverFactory): DnsClient {
        dnsQueryLifecycleObserverFactory = lifecycleObserverFactory
        return this
    }

    /**
     * Sets the cache for authoritative NS servers
     *
     * @param authoritativeDnsServerCache the authoritative NS servers cache
     *
     * @return `this`
     */
    fun authoritativeDnsServerCache(authoritativeDnsServerCache: DnsCache): DnsClient {
        this.authoritativeDnsServerCache = authoritativeDnsServerCache
        return this
    }

    /**
     * Sets the minimum and maximum TTL of the cached DNS resource records (in seconds). If the TTL of the DNS
     * resource record returned by the DNS server is less than the minimum TTL or greater than the maximum TTL,
     * this resolver will ignore the TTL from the DNS server and use the minimum TTL or the maximum TTL instead
     * respectively.
     * The default value is `0` and [Integer.MAX_VALUE], which practically tells this resolver to
     * respect the TTL from the DNS server.
     *
     * @param minTtl the minimum TTL
     * @param maxTtl the maximum TTL
     *
     * @return `this`
     */
    fun ttl(minTtl: Int, maxTtl: Int): DnsClient {
        this.maxTtl = maxTtl
        this.minTtl = minTtl
        return this
    }

    /**
     * Sets the TTL of the cache for the failed DNS queries (in seconds).
     *
     * @param negativeTtl the TTL for failed cached queries
     *
     * @return `this`
     */
    fun negativeTtl(negativeTtl: Int): DnsClient {
        this.negativeTtl = negativeTtl
        return this
    }

    /**
     * Sets the timeout of each DNS query performed by this resolver (in milliseconds).
     *
     * @param queryTimeoutMillis the query timeout
     *
     * @return `this`
     */
    fun queryTimeoutMillis(queryTimeoutMillis: Long): DnsClient {
        this.queryTimeoutMillis = queryTimeoutMillis
        return this
    }

    /**
     * Sets the list of the protocol families of the address resolved.
     * You can use [DnsClient.computeResolvedAddressTypes]
     * to get a [ResolvedAddressTypes] out of some [InternetProtocolFamily]s.
     *
     * @param resolvedAddressTypes the address types
     *
     * @return `this`
     */
    fun resolvedAddressTypes(resolvedAddressTypes: ResolvedAddressTypes): DnsClient {
        this.resolvedAddressTypes = resolvedAddressTypes
        return this
    }

    /**
     * Sets if this resolver has to send a DNS query with the RD (recursion desired) flag set.
     *
     * @param recursionDesired true if recursion is desired
     *
     * @return `this`
     */
    fun recursionDesired(recursionDesired: Boolean): DnsClient {
        this.recursionDesired = recursionDesired
        return this
    }

    /**
     * Sets the maximum allowed number of DNS queries to send when resolving a host name.
     *
     * @param maxQueriesPerResolve the max number of queries
     *
     * @return `this`
     */
    fun maxQueriesPerResolve(maxQueriesPerResolve: Int): DnsClient {
        this.maxQueriesPerResolve = maxQueriesPerResolve
        return this
    }

    /**
     * Sets if this resolver should generate the detailed trace information in an exception message so that
     * it is easier to understand the cause of resolution failure.
     *
     * @param traceEnabled true if trace is enabled
     *
     * @return `this`
     */
    fun traceEnabled(traceEnabled: Boolean): DnsClient {
        this.traceEnabled = traceEnabled
        return this
    }

    /**
     * Sets the capacity of the datagram packet buffer (in bytes).  The default value is `4096` bytes.
     *
     * @param maxPayloadSize the capacity of the datagram packet buffer
     *
     * @return `this`
     */
    fun maxPayloadSize(maxPayloadSize: Int): DnsClient {
        this.maxPayloadSize = maxPayloadSize
        return this
    }

    /**
     * Set the [DnsServerAddressStreamProvider] which is used to determine which DNS server is used to resolve
     * each hostname.
     *
     * @return `this`
     */
    fun nameServerProvider(dnsServerAddressStreamProvider: DnsServerAddressStreamProvider?): DnsClient {
        if (dnsServerAddressStreamProvider == null) {
            throw NullPointerException("dnsServerAddressStreamProvider")
        }
        this.dnsServerAddressStreamProvider = dnsServerAddressStreamProvider
        return this
    }

    /**
     * Set the list of search domains of the resolver.
     *
     * @param searchDomains the search domains
     *
     * @return `this`
     */
    fun searchDomains(searchDomains: Iterable<String?>?): DnsClient {
        if (searchDomains == null) {
            throw NullPointerException("searchDomains")
        }

        val list: MutableList<String> = ArrayList(4)
        for (f in searchDomains) {
            if (f == null) {
                break
            }

            // Avoid duplicate entries.
            if (list.contains(f)) {
                continue
            }
            list.add(f)
        }
        this.searchDomains = list.toTypedArray()
        return this
    }

    /**
     * Set the number of dots which must appear in a name before an initial absolute query is made.
     * The default value is `1`.
     *
     * @param ndots the ndots value
     *
     * @return `this`
     */
    fun ndots(ndots: Int): DnsClient {
        this.ndots = ndots
        return this
    }

    private fun newCache(): DnsCache {
        return DefaultDnsCache(minTtl, maxTtl, negativeTtl)
    }

    /**
     * Set if domain / host names should be decoded to unicode when received.
     * See [rfc3492](https://tools.ietf.org/html/rfc3492).
     *
     * @param decodeIdn if should get decoded
     *
     * @return `this`
     */
    fun decodeToUnicode(decodeIdn: Boolean): DnsClient {
        this.decodeIdn = decodeIdn
        return this
    }

    /**
     * Starts the DNS Name Resolver for the client, which will resolve DNS queries.
     */
    fun start(): DnsClient {
        val channelFactory = ReflectiveChannelFactory(channelType)

        // if (resolveCache != null && (minTtl != 0 || maxTtl != Integer.MAX_VALUE || negativeTtl != 0)) {
        check(!(resolveCache != null && (minTtl != 0 || maxTtl != Int.MAX_VALUE || negativeTtl != 0))) {
            "resolveCache and TTLs are mutually exclusive"
        }
        check(!(authoritativeDnsServerCache != null && (minTtl != 0 || maxTtl != Int.MAX_VALUE || negativeTtl != 0))) {
            "authoritativeDnsServerCache and TTLs are mutually exclusive"
        }


        resolver = DnsNameResolver(
            eventLoopGroup!!.next(),
            channelFactory,
            resolveCache ?: newCache(),
            authoritativeDnsServerCache ?: newCache(),
            dnsQueryLifecycleObserverFactory,
            queryTimeoutMillis,
            resolvedAddressTypes,
            recursionDesired,
            maxQueriesPerResolve,
            traceEnabled,
            maxPayloadSize,
            dnsServerAddressStreamProvider,
            searchDomains,
            ndots,
            decodeIdn
        )
        return this
    }

    /**
     * Clears the DNS resolver cache
     */
    fun reset() {
        if (resolver == null) {
            start()
        }
        clearResolver()
    }

    private fun clearResolver() {
        resolver!!.resolveCache().clear()
    }

    override fun stopExtraActions() {
        if (resolver != null) {
            clearResolver()
            resolver!!.close() // also closes the UDP channel that DNS client uses
        }
    }

    /**
     * Resolves a specific hostname A/AAAA record with the default timeout of 5 seconds
     *
     * @param hostname the hostname, ie: google.com, that you want to resolve
     * @param queryTimeoutSeconds the number of seconds to wait for host resolution
     *
     * @return the list of resolved InetAddress or throws an exception if the hostname cannot be resolved or null if not possible
     */
    @Throws(UnknownHostException::class)
    fun resolve(hostname: String?, queryTimeoutSeconds: Int = 5): List<InetAddress>? {
        if (hostname == null) {
            throw UnknownHostException("Cannot submit query for an unknown host")
        }
        if (resolver == null) {
            start()
        }

        // use "resolve", since it handles A/AAAA records + redirects correctly
        val resolve = resolver!!.resolveAll(hostname)
        val finished = resolve.awaitUninterruptibly(queryTimeoutSeconds.toLong(), TimeUnit.SECONDS)

        // now return whatever value we had
        if (finished && resolve.isSuccess && resolve.isDone) {
            return try {
                resolve.now
            } catch (e: Exception) {
                logger.error("Could not ask question to DNS server for: $hostname", e)
                return null
            }
        }
        logger.error("Could not ask question to DNS server for: $hostname")
        return null
    }


    /**
     * Resolves a specific hostname record, of the specified type (PTR, MX, TXT, etc)
     *
     * Note: PTR queries absolutely MUST end in '.in-addr.arpa' in order for the DNS server to understand it.
     * -- because of this, we will automatically fix this in case that clients are unaware of this requirement
     *
     * Note: A/AAAA queries absolutely MUST end in a '.' -- because of this we will automatically fix this in case that clients are
     * unaware of this requirement
     *
     * @param hostname the hostname, ie: google.com, that you want to resolve
     * @param type     the DnsRecordType you want to resolve (PTR, MX, TXT, etc)
     * @param queryTimeoutSeconds the number of seconds to wait for host resolution
     *
     * @return the DnsRecords or throws an exception if the hostname cannot be resolved or null if it could not be resolved
     */
    @Throws(UnknownHostException::class)
    fun query(hostname: String, type: Int, queryTimeoutSeconds: Int = 5): List<DnsRecord>? {
        if (resolver == null) {
            start()
        }

        // we use our own resolvers
        val dnsMessage = DnsQuestion.newQuery(hostname, type, recursionDesired)
        return query(dnsMessage, queryTimeoutSeconds)
    }

    /**
     * Resolves a specific DnsQuestion
     *
     *
     *
     *
     * Note: PTR queries absolutely MUST end in '.in-addr.arpa' in order for the DNS server to understand it.
     * -- because of this, we will automatically fix this in case that clients are unaware of this requirement
     *
     *
     *
     *
     * Note: A/AAAA queries absolutely MUST end in a '.' -- because of this we will automatically fix this in case that clients are
     * unaware of this requirement
     *
     * @param queryTimeoutSeconds the number of seconds to wait for host resolution
     *
     * @return the DnsRecords or throws an exception if the hostname cannot be resolved or null if it could not be resolved
     */
    @Throws(UnknownHostException::class)
    fun query(dnsMessage: DnsQuestion, queryTimeoutSeconds: Int): List<DnsRecord>? {
        val questionCount = dnsMessage.header.getCount(DnsSection.QUESTION)
        if (questionCount > 1) {
            throw UnknownHostException("Cannot ask more than 1 question at a time! You tried to ask $questionCount questions at once")
        }

        val type = dnsMessage.question!!.type
        val query = resolver!!.query(dnsMessage)
        val finished = query.awaitUninterruptibly(queryTimeoutSeconds.toLong(), TimeUnit.SECONDS)

        // now return whatever value we had
        if (finished && query.isSuccess && query.isDone) {
            val response = query.now
            try {
                val code = response.header.rcode
                if (code == DnsResponseCode.NOERROR) {
                    return response.getSectionArray(DnsSection.ANSWER).toList()
                }
                val msg =
                    "Could not ask question to DNS server: Error code " + code + " for type: " + type + " - " + DnsRecordType.string(type)
                logger.error(msg)
                return null
            } finally {
                response.release()
            }
        }

        logger.error("Could not ask question to DNS server for type: " + DnsRecordType.string(type))
        return null
    }
}
