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
package dorkbox.dns.dns.resolver

import dorkbox.dns.dns.DnsQuestion
import dorkbox.dns.dns.DnsQuestion.Companion.hostNameAsciiFix
import dorkbox.dns.dns.clientHandlers.DatagramDnsQueryEncoder
import dorkbox.dns.dns.clientHandlers.DatagramDnsResponseDecoder
import dorkbox.dns.dns.clientHandlers.DnsResponse
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.resolver.addressProvider.DefaultDnsServerAddressStreamProvider
import dorkbox.dns.dns.resolver.addressProvider.DnsServerAddressStream
import dorkbox.dns.dns.resolver.addressProvider.DnsServerAddressStreamProvider
import dorkbox.dns.dns.resolver.addressProvider.DnsServerAddresses
import dorkbox.dns.dns.resolver.cache.DnsCache
import dorkbox.netUtil.Dns.defaultNameServers
import dorkbox.netUtil.Dns.numberDots
import dorkbox.netUtil.Dns.resolveFromHosts
import dorkbox.netUtil.IP.isValid
import dorkbox.netUtil.IP.toBytes
import dorkbox.netUtil.IP.toString
import dorkbox.netUtil.IPv4
import dorkbox.netUtil.IPv6
import dorkbox.netUtil.dnsUtils.ResolvedAddressTypes
import dorkbox.os.OS.isWindows
import io.netty.bootstrap.Bootstrap
import io.netty.channel.Channel
import io.netty.channel.ChannelFactory
import io.netty.channel.ChannelFutureListener
import io.netty.channel.ChannelInitializer
import io.netty.channel.ChannelOption
import io.netty.channel.ChannelPromise
import io.netty.channel.EventLoop
import io.netty.channel.FixedRecvByteBufAllocator
import io.netty.channel.socket.DatagramChannel
import io.netty.channel.socket.InternetProtocolFamily
import io.netty.resolver.InetNameResolver
import io.netty.util.concurrent.FastThreadLocal
import io.netty.util.concurrent.Future
import io.netty.util.concurrent.Promise
import io.netty.util.internal.ObjectUtil
import io.netty.util.internal.UnstableApi
import org.slf4j.LoggerFactory
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.function.*

/**
 * A DNS-based [InetNameResolver]
 */
@UnstableApi
class DnsNameResolver(
    eventLoop: EventLoop,
    channelFactory: ChannelFactory<out DatagramChannel>,
    resolveCache: DnsCache,
    authoritativeDnsServerCache: DnsCache,
    dnsQueryLifecycleObserverFactory: DnsQueryLifecycleObserverFactory,
    queryTimeoutMillis: Long,
    resolvedAddressTypes: ResolvedAddressTypes?,
    recursionDesired: Boolean,
    maxQueriesPerResolve: Int,
    traceEnabled: Boolean,
    maxPayloadSize: Int,
    dnsServerAddressStreamProvider: DnsServerAddressStreamProvider,
    searchDomains: Array<String>?,
    ndots: Int,
    decodeIdn: Boolean
) : InetNameResolver(eventLoop) {
    private val DNS_ENCODER: DatagramDnsQueryEncoder
    val channelFuture: Future<Channel>
    val ch: DatagramChannel

    /**
     * Manages the [DnsQueryContext]s in progress and their query IDs.
     */
    internal val queryContextManager = DnsQueryContextManager()

    /**
     * Cache for [.doResolve] and [.doResolveAll].
     */
    private val resolveCache: DnsCache
    private val authoritativeDnsServerCache: DnsCache
    private val queryTimeoutMillis: Long
    private val maxQueriesPerResolve: Int
    private val resolvedAddressTypes: ResolvedAddressTypes
    private val resolvedInternetProtocolFamilies: Array<InternetProtocolFamily>

    /**
     * Returns `true` if and only if this resolver sends a DNS query with the RD (recursion desired) flag set.
     * The default value is `true`.
     */
    val isRecursionDesired: Boolean
    private val maxPayloadSize: Int
    private val dnsServerAddressStreamProvider: DnsServerAddressStreamProvider
    private val nameServerAddrStream: FastThreadLocal<DnsServerAddressStream> = object : FastThreadLocal<DnsServerAddressStream>() {
        @Throws(Exception::class)
        override fun initialValue(): DnsServerAddressStream {
            return dnsServerAddressStreamProvider.nameServerAddressStream("")
        }
    }
    private val searchDomains: Array<String>
    private val ndots: Int
    private var supportsAAAARecords = false
    private var supportsARecords = false
    private var preferredAddressType: InternetProtocolFamily
    private val resolveRecordTypes: IntArray
    val isDecodeIdn: Boolean

    private var dnsQueryLifecycleObserverFactory: DnsQueryLifecycleObserverFactory? = null

    /**
     * Creates a new DNS-based name resolver that communicates with the specified list of DNS servers.
     *
     * @param eventLoop the [EventLoop] which will perform the communication with the DNS servers
     * @param channelFactory the [ChannelFactory] that will create a [DatagramChannel]
     * @param resolveCache the DNS resolved entries cache
     * @param authoritativeDnsServerCache the cache used to find the authoritative DNS server for a domain
     * @param dnsQueryLifecycleObserverFactory used to generate new instances of [DnsQueryLifecycleObserver] which
     * can be used to track metrics for DNS servers.
     * @param queryTimeoutMillis timeout of each DNS query in millis
     * @param resolvedAddressTypes the preferred address types
     * @param recursionDesired if recursion desired flag must be set
     * @param maxQueriesPerResolve the maximum allowed number of DNS queries for a given name resolution
     * @param traceEnabled if trace is enabled
     * @param maxPayloadSize the capacity of the datagram packet buffer
     * @param dnsServerAddressStreamProvider The [DnsServerAddressStreamProvider] used to determine the name
     * servers for each hostname lookup.
     * @param searchDomains the list of search domain
     * (can be null, if so, will try to default to the underlying platform ones)
     * @param ndots the ndots value
     * @param decodeIdn `true` if domain / host names should be decoded to unicode when received.
     * See [rfc3492](https://tools.ietf.org/html/rfc3492).
     */
    init {
        this.queryTimeoutMillis = ObjectUtil.checkPositive(queryTimeoutMillis, "queryTimeoutMillis")
        this.resolvedAddressTypes = resolvedAddressTypes ?: DEFAULT_RESOLVE_ADDRESS_TYPES!!
        isRecursionDesired = recursionDesired
        this.maxQueriesPerResolve = ObjectUtil.checkPositive(maxQueriesPerResolve, "maxQueriesPerResolve")
        this.maxPayloadSize = ObjectUtil.checkPositive(maxPayloadSize, "maxPayloadSize")
        this.dnsServerAddressStreamProvider = ObjectUtil.checkNotNull(dnsServerAddressStreamProvider, "dnsServerAddressStreamProvider")
        this.resolveCache = ObjectUtil.checkNotNull(resolveCache, "resolveCache")
        this.authoritativeDnsServerCache = ObjectUtil.checkNotNull(authoritativeDnsServerCache, "authoritativeDnsServerCache")
        if (traceEnabled) {
            if (dnsQueryLifecycleObserverFactory is NoopDnsQueryLifecycleObserverFactory) {
                this.dnsQueryLifecycleObserverFactory = TraceDnsQueryLifeCycleObserverFactory()
            } else {
                this.dnsQueryLifecycleObserverFactory = BiDnsQueryLifecycleObserverFactory(
                    TraceDnsQueryLifeCycleObserverFactory(), dnsQueryLifecycleObserverFactory
                )
            }
        } else {
            this.dnsQueryLifecycleObserverFactory =
                ObjectUtil.checkNotNull(dnsQueryLifecycleObserverFactory, "dnsQueryLifecycleObserverFactory")
        }
        this.searchDomains = searchDomains?.clone() ?: DEFAULT_SEARCH_DOMAINS
        this.ndots = if (ndots >= 0) ndots else DEFAULT_NDOTS
        isDecodeIdn = decodeIdn

        when (this.resolvedAddressTypes) {
            ResolvedAddressTypes.IPV4_ONLY -> {
                supportsAAAARecords = false
                supportsARecords = true
                resolveRecordTypes = IPV4_ONLY_RESOLVED_RECORD_TYPES
                resolvedInternetProtocolFamilies = IPV4_ONLY_RESOLVED_PROTOCOL_FAMILIES
                preferredAddressType = InternetProtocolFamily.IPv4
            }
            ResolvedAddressTypes.IPV4_PREFERRED -> {
                supportsAAAARecords = true
                supportsARecords = true
                resolveRecordTypes = IPV4_PREFERRED_RESOLVED_RECORD_TYPES
                resolvedInternetProtocolFamilies = IPV4_PREFERRED_RESOLVED_PROTOCOL_FAMILIES
                preferredAddressType = InternetProtocolFamily.IPv4
            }
            ResolvedAddressTypes.IPV6_ONLY -> {
                supportsAAAARecords = true
                supportsARecords = false
                resolveRecordTypes = IPV6_ONLY_RESOLVED_RECORD_TYPES
                resolvedInternetProtocolFamilies = IPV6_ONLY_RESOLVED_PROTOCOL_FAMILIES
                preferredAddressType = InternetProtocolFamily.IPv6
            }
            ResolvedAddressTypes.IPV6_PREFERRED -> {
                supportsAAAARecords = true
                supportsARecords = true
                resolveRecordTypes = IPV6_PREFERRED_RESOLVED_RECORD_TYPES
                resolvedInternetProtocolFamilies = IPV6_PREFERRED_RESOLVED_PROTOCOL_FAMILIES
                preferredAddressType = InternetProtocolFamily.IPv6
            }
            else -> throw IllegalArgumentException("Unknown ResolvedAddressTypes $resolvedAddressTypes")
        }
        val b = Bootstrap()
        b.group(executor())
        b.channelFactory(channelFactory)
        b.option(ChannelOption.DATAGRAM_CHANNEL_ACTIVE_ON_REGISTRATION, true)
        DNS_ENCODER = DatagramDnsQueryEncoder(maxPayloadSize)
        val channelActivePromise = executor().newPromise<Channel>()
        val responseHandler = DnsNameResolverResponseHandler(this, channelActivePromise)
        b.handler(object : ChannelInitializer<DatagramChannel>() {
            @Throws(Exception::class)
            override fun initChannel(ch: DatagramChannel) {
                ch.pipeline().addLast(DNS_DECODER, DNS_ENCODER, responseHandler)
            }
        })
        channelFuture = channelActivePromise
        ch = b.register().channel() as DatagramChannel
        ch.config().setRecvByteBufAllocator(FixedRecvByteBufAllocator(maxPayloadSize))
        ch.closeFuture().addListener(ChannelFutureListener { resolveCache.clear() })
    }

    public override fun executor(): EventLoop {
        return super.executor() as EventLoop
    }

    @Throws(Exception::class)
    override fun doResolve(inetHost: String, promise: Promise<InetAddress>) {
        doResolve(inetHost, promise, resolveCache)
    }

    @Throws(Exception::class)
    override fun doResolveAll(inetHost: String, promise: Promise<List<InetAddress>>) {
        doResolveAll(inetHost, promise, resolveCache)
    }

    /**
     * Closes the internal datagram channel used for sending and receiving DNS messages, and clears all DNS resource
     * records from the cache. Attempting to send a DNS query or to resolve a domain name will fail once this method
     * has been called.
     */
    override fun close() {
        if (ch.isOpen) {
            ch.close()
        }
    }

    /**
     * Hook designed for extensibility so one can pass a different cache on each resolution attempt
     * instead of using the global one.
     */
    @Throws(Exception::class)
    protected fun doResolveAll(inetHost: String?, promise: Promise<List<InetAddress>>, resolveCache: DnsCache) {
        if (inetHost == null || inetHost.isEmpty()) {
            // If an empty hostname is used we should use "localhost", just like InetAddress.getAllByName(...) does.
            promise.setSuccess(listOf(loopbackAddress()))
            return
        }
        if (isValid(inetHost)) {
            val bytes = toBytes(inetHost)
            if (bytes.size > 0) {
                // The unresolvedAddress was created via a String that contains an ip address.
                promise.setSuccess(listOf(InetAddress.getByAddress(bytes)))
                return
            }
        }
        val hostname = hostNameAsciiFix(inetHost)
        val hostsFileEntry = resolveHostsFileEntry(hostname)
        if (hostsFileEntry != null) {
            promise.setSuccess(listOf(hostsFileEntry))
            return
        }
        if (!doResolveAllCached(hostname, promise, resolveCache)) {
            doResolveAllUncached(hostname!!, promise, resolveCache)
        }
    }

    private fun doResolveAllCached(hostname: String?, promise: Promise<List<InetAddress>>, resolveCache: DnsCache): Boolean {
        if (hostname == null) {
            return false
        }

        val cachedEntries = resolveCache[hostname]
        if (cachedEntries == null || cachedEntries.isEmpty()) {
            return false
        }
        var result: MutableList<InetAddress>? = null
        var cause: Throwable? = null
        synchronized(cachedEntries) {
            val numEntries = cachedEntries.size
            assert(numEntries > 0)
            if (cachedEntries[0].cause() != null) {
                cause = cachedEntries[0].cause()
            } else {
                for (f in resolvedInternetProtocolFamilies) {
                    for (i in 0 until numEntries) {
                        val e = cachedEntries[i]
                        if (f.addressType().isInstance(e.address())) {
                            if (result == null) {
                                result = ArrayList(numEntries)
                            }
                            result!!.add(e.address()!!)
                        }
                    }
                }
            }
        }
        if (result != null) {
            trySuccess(promise, result!!)
            return true
        }
        if (cause != null) {
            tryFailure(promise, cause!!)
            return true
        }
        return false
    }

    private fun doResolveAllUncached(hostname: String, promise: Promise<List<InetAddress>>, resolveCache: DnsCache) {
        val nameServerAddrs = dnsServerAddressStreamProvider.nameServerAddressStream(hostname)
        val context = DnsNameResolverListResolverContext(this, hostname, resolveCache, nameServerAddrs)
        context.resolve(promise)
    }

    /**
     * Hook designed for extensibility so one can pass a different cache on each resolution attempt
     * instead of using the global one.
     */
    @Throws(Exception::class)
    protected fun doResolve(inetHost: String?, promise: Promise<InetAddress>, resolveCache: DnsCache) {
        if (inetHost == null || inetHost.isEmpty()) {
            // If an empty hostname is used we should use "localhost", just like InetAddress.getByName(...) does.
            promise.setSuccess(loopbackAddress())
            return
        }
        val bytes = toBytes(inetHost)
        if (bytes != null) {
            // The inetHost is actually an ipaddress.
            promise.setSuccess(InetAddress.getByAddress(bytes))
            return
        }
        val hostname = hostNameAsciiFix(inetHost)
        val hostsFileEntry = resolveHostsFileEntry(hostname)
        if (hostsFileEntry != null) {
            promise.setSuccess(hostsFileEntry)
            return
        }
        if (!doResolveCached(hostname, promise, resolveCache)) {
            doResolveUncached(hostname!!, promise, resolveCache)
        }
    }

    fun resolveHostsFileEntry(hostname: String?): InetAddress? {
        val address = resolveFromHosts(hostname!!, resolvedAddressTypes)
        return if (address == null && isWindows && LOCALHOST.equals(hostname, ignoreCase = true)) {
            // If we tried to resolve localhost we need workaround that windows removed localhost from its hostfile in later versions.
            // See https://github.com/netty/netty/issues/5386
            LOCALHOST_ADDRESS
        } else address
    }

    private fun loopbackAddress(): InetAddress {
        return preferredAddressType()!!.localhost()
    }

    fun preferredAddressType(): InternetProtocolFamily {
        return preferredAddressType
    }

    private fun doResolveCached(hostname: String?, promise: Promise<InetAddress>, resolveCache: DnsCache): Boolean {
        if (hostname == null) {
            return false
        }

        val cachedEntries = resolveCache[hostname]
        if (cachedEntries == null || cachedEntries.isEmpty()) {
            return false
        }
        var address: InetAddress? = null
        var cause: Throwable? = null
        var arrayList: ArrayList<InetAddress?>
        synchronized(cachedEntries) {
            val numEntries = cachedEntries.size
            assert(numEntries > 0)
            if (cachedEntries[0].cause() != null) {
                cause = cachedEntries[0].cause()
            } else {
                // Find the first entry with the preferred address type.
                for (f in resolvedInternetProtocolFamilies) {
                    for (i in 0 until numEntries) {
                        val e = cachedEntries[i]
                        if (f.addressType().isInstance(e.address())) {
                            address = e.address()
                            break
                        }
                    }
                }
            }
        }
        if (address != null) {
            trySuccess(promise, address!!)
            return true
        }
        if (cause != null) {
            tryFailure(promise, cause!!)
            return true
        }
        return false
    }

    private fun doResolveUncached(hostname: String, promise: Promise<InetAddress>, resolveCache: DnsCache) {
        DnsNameResolverSingleResolverContext(this, hostname, resolveCache, dnsServerAddressStreamProvider.nameServerAddressStream(hostname)).resolve(promise)
    }

    // Only here to override in unit tests.
    fun dnsRedirectPort(server: InetAddress?): Int {
        return DefaultDnsServerAddressStreamProvider.DNS_PORT
    }

    fun dnsQueryLifecycleObserverFactory(): DnsQueryLifecycleObserverFactory? {
        return dnsQueryLifecycleObserverFactory
    }

    /**
     * Provides the opportunity to sort the name servers before following a redirected DNS query.
     *
     * @param nameServers The addresses of the DNS servers which are used in the event of a redirect.
     *
     * @return A [DnsServerAddressStream] which will be used to follow the DNS redirect.
     */
    fun uncachedRedirectDnsServerStream(nameServers: List<InetSocketAddress>): DnsServerAddressStream {
        return DnsServerAddresses.sequential(nameServers).stream()
    }

    /**
     * Returns the resolution cache.
     */
    fun resolveCache(): DnsCache {
        return resolveCache
    }

    /**
     * Returns the cache used for authoritative DNS servers for a domain.
     */
    fun authoritativeDnsServerCache(): DnsCache {
        return authoritativeDnsServerCache
    }

    /**
     * Returns the timeout of each DNS query performed by this resolver (in milliseconds).
     * The default value is 5 seconds.
     */
    fun queryTimeoutMillis(): Long {
        return queryTimeoutMillis
    }

    /**
     * Returns the [ResolvedAddressTypes] resolved by [.resolve].
     * The default value depends on the value of the system property `"java.net.preferIPv6Addresses"`.
     */
    fun resolvedAddressTypes(): ResolvedAddressTypes {
        return resolvedAddressTypes
    }

    fun resolvedInternetProtocolFamiliesUnsafe(): Array<InternetProtocolFamily> {
        return resolvedInternetProtocolFamilies
    }

    fun searchDomains(): Array<String> {
        return searchDomains
    }

    fun ndots(): Int {
        return ndots
    }

    fun supportsAAAARecords(): Boolean {
        return supportsAAAARecords
    }

    fun supportsARecords(): Boolean {
        return supportsARecords
    }

    fun resolveRecordTypes(): IntArray {
        return resolveRecordTypes
    }

    /**
     * Returns the maximum allowed number of DNS queries to send when resolving a host name.
     * The default value is `8`.
     */
    fun maxQueriesPerResolve(): Int {
        return maxQueriesPerResolve
    }

    /**
     * Returns the capacity of the datagram packet buffer (in bytes).  The default value is `4096` bytes.
     */
    fun maxPayloadSize(): Int {
        return maxPayloadSize
    }

    /**
     * @return resolve hostnames against the hosts file
     */
    fun hostsFileEntriesResolver(hostname: String?, type: ResolvedAddressTypes?): InetAddress? {
        return resolveFromHosts(hostname!!, type!!)
    }

    /**
     * Resolves the specified name into an address.
     *
     * @param inetHost the name to resolve
     * @param promise the [Promise] which will be fulfilled when the name resolution is finished
     *
     * @return the address as the result of the resolution
     */
    override fun resolve(inetHost: String, promise: Promise<InetAddress>): Future<InetAddress> {
        ObjectUtil.checkNotNull(promise, "promise")
        return try {
            doResolve(inetHost, promise, resolveCache)
            promise
        } catch (e: Exception) {
            promise.setFailure(e)
        }
    }

    /**
     * Resolves the specified host name and port into a list of address.
     *
     * @param inetHost the name to resolve
     * @param promise the [Promise] which will be fulfilled when the name resolution is finished
     *
     * @return the list of the address as the result of the resolution
     */
    override fun resolveAll(inetHost: String, promise: Promise<List<InetAddress>>): Future<List<InetAddress>> {
        ObjectUtil.checkNotNull(promise, "promise")
        return try {
            doResolveAll(inetHost, promise, resolveCache)
            promise
        } catch (e: Exception) {
            promise.setFailure(e)
        }
    }

    /**
     * Sends a DNS query with the specified question.
     */
    fun query(question: DnsQuestion): Future<DnsResponse> {
        return query(nextNameServerAddress(), question)
    }

    private fun nextNameServerAddress(): InetSocketAddress {
        return nameServerAddrStream.get().next()!!
    }

    /**
     * Sends a DNS query with the specified question using the specified name server list.
     */
    fun query(nameServerAddr: InetSocketAddress, question: DnsQuestion): Future<DnsResponse> {
        return query0(nameServerAddr, question, ch.eventLoop().newPromise())
    }

    fun query0(nameServerAddr: InetSocketAddress, question: DnsQuestion, promise: Promise<DnsResponse>): Future<DnsResponse> {
        return query0(nameServerAddr, question, ch.newPromise(), promise)
    }

    fun query0(
        nameServerAddr: InetSocketAddress, question: DnsQuestion, writePromise: ChannelPromise?, promise: Promise<DnsResponse>
    ): Future<DnsResponse> {
        assert(!writePromise!!.isVoid)
        return try {
            DnsQueryContext(this, nameServerAddr, question, promise).query(writePromise)
            promise
        } catch (e: Exception) {
            promise.setFailure(e)
        }
    }

    /**
     * Sends a DNS query with the specified question.
     */
    fun query(question: DnsQuestion, promise: Promise<DnsResponse>): Future<DnsResponse> {
        return query(nextNameServerAddress(), question, promise)
    }

    /**
     * Sends a DNS query with the specified question using the specified name server list.
     */
    fun query(nameServerAddr: InetSocketAddress, question: DnsQuestion, promise: Promise<DnsResponse>): Future<DnsResponse> {
        return query0(nameServerAddr, question, null, promise)
    }

    companion object {
        val logger = LoggerFactory.getLogger(DnsNameResolver::class.java)

        private const val LOCALHOST = "localhost"
        private val LOCALHOST_ADDRESS: InetAddress

        private val IPV4_ONLY_RESOLVED_RECORD_TYPES = intArrayOf(DnsRecordType.A)
        private val IPV4_ONLY_RESOLVED_PROTOCOL_FAMILIES = arrayOf(InternetProtocolFamily.IPv4)
        private val IPV4_PREFERRED_RESOLVED_RECORD_TYPES = intArrayOf(DnsRecordType.A, DnsRecordType.AAAA)
        private val IPV4_PREFERRED_RESOLVED_PROTOCOL_FAMILIES = arrayOf(InternetProtocolFamily.IPv4, InternetProtocolFamily.IPv6)

        private val IPV6_ONLY_RESOLVED_RECORD_TYPES = intArrayOf(DnsRecordType.AAAA)
        private val IPV6_ONLY_RESOLVED_PROTOCOL_FAMILIES = arrayOf(InternetProtocolFamily.IPv6)
        private val IPV6_PREFERRED_RESOLVED_RECORD_TYPES = intArrayOf(DnsRecordType.AAAA, DnsRecordType.A)
        private val IPV6_PREFERRED_RESOLVED_PROTOCOL_FAMILIES = arrayOf(InternetProtocolFamily.IPv6, InternetProtocolFamily.IPv4)

        val DEFAULT_RESOLVE_ADDRESS_TYPES: ResolvedAddressTypes
        val DEFAULT_SEARCH_DOMAINS: Array<String>

        private val DEFAULT_NDOTS: Int
        private val DNS_DECODER = DatagramDnsResponseDecoder()

        init {
            if (IPv4.isPreferred) {
                DEFAULT_RESOLVE_ADDRESS_TYPES = ResolvedAddressTypes.IPV4_ONLY
                LOCALHOST_ADDRESS = IPv4.LOCALHOST
            } else {
                if (IPv6.isPreferred) {
                    DEFAULT_RESOLVE_ADDRESS_TYPES = ResolvedAddressTypes.IPV6_PREFERRED
                    LOCALHOST_ADDRESS = IPv6.LOCALHOST
                } else {
                    DEFAULT_RESOLVE_ADDRESS_TYPES = ResolvedAddressTypes.IPV4_PREFERRED
                    LOCALHOST_ADDRESS = IPv4.LOCALHOST
                }
            }

            val searchDomains = defaultNameServers
            DEFAULT_SEARCH_DOMAINS = searchDomains.map { toString(it.address, false) }.toTypedArray()
            DEFAULT_NDOTS = numberDots
        }

        fun <T> trySuccess(promise: Promise<T>, result: T) {
            if (!promise.trySuccess(result)) {
                logger.warn("Failed to notify success ({}) to a promise: {}", result, promise)
            }
        }

        private fun tryFailure(promise: Promise<*>, cause: Throwable) {
            if (!promise.tryFailure(cause)) {
                logger.warn("Failed to notify failure to a promise: {}", promise, cause)
            }
        }
    }
}
