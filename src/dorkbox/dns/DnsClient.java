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
package dorkbox.dns;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;

import dorkbox.dns.dns.DnsQuestion;
import dorkbox.dns.dns.clientHandlers.DnsResponse;
import dorkbox.dns.dns.constants.DnsRecordType;
import dorkbox.dns.dns.constants.DnsResponseCode;
import dorkbox.dns.dns.constants.DnsSection;
import dorkbox.dns.dns.records.DnsRecord;
import dorkbox.dns.dns.resolver.DnsNameResolver;
import dorkbox.dns.dns.resolver.DnsQueryLifecycleObserverFactory;
import dorkbox.dns.dns.resolver.NoopDnsQueryLifecycleObserverFactory;
import dorkbox.dns.dns.resolver.addressProvider.DefaultDnsServerAddressStreamProvider;
import dorkbox.dns.dns.resolver.addressProvider.DnsServerAddressStreamProvider;
import dorkbox.dns.dns.resolver.addressProvider.SequentialDnsServerAddressStreamProvider;
import dorkbox.dns.dns.resolver.cache.DefaultDnsCache;
import dorkbox.dns.dns.resolver.cache.DnsCache;
import dorkbox.dns.util.NativeLibrary;
import dorkbox.dns.util.Shutdownable;
import dorkbox.netUtil.Dns;
import dorkbox.netUtil.dnsUtils.ResolvedAddressTypes;
import dorkbox.os.OS;
import dorkbox.util.NamedThreadFactory;
import io.netty.channel.ChannelFactory;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.ReflectiveChannelFactory;
import io.netty.channel.socket.DatagramChannel;
import io.netty.channel.socket.InternetProtocolFamily;
import io.netty.util.concurrent.Future;

/**
 * A DnsClient for resolving DNS name, with reasonably good defaults.
 */
@SuppressWarnings({"unused", "WeakerAccess"})
public
class DnsClient extends Shutdownable {


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
    public static
    String getVersion() {
        return "1.5";
    }

    static {
        // Add this project to the updates system, which verifies this class + UUID + version information
        dorkbox.updates.Updates.INSTANCE.add(DnsClient.class, "5d805c5503b64becb0e206480d07035e", getVersion());
    }

    /**
     * Retrieve the public facing IP address of this system using DNS.
     * <p/>
     * Same command as
     * <p/>
     * dig +short myip.opendns.com @resolver1.opendns.com
     *
     * @return the public IP address if found, or null if it didn't find it
     */
    public static
    InetAddress getPublicIp() {
        final InetSocketAddress dnsServer = new InetSocketAddress("208.67.222.222", 53);  // openDNS

        DnsClient dnsClient = new DnsClient(dnsServer);
        List<InetAddress> resolved = null;
        try {
            resolved = dnsClient.resolve("myip.opendns.com");
        } catch (Throwable ignored) {
        }

        dnsClient.stop();

        if (resolved != null && resolved.size() > 0) {
            return resolved.get(0);
        }

        return null;
    }

    private final Logger logger = org.slf4j.LoggerFactory.getLogger(getClass());
    private Class<? extends DatagramChannel> channelType;

    private DnsNameResolver resolver;

    private ThreadGroup threadGroup;
    private static final String THREAD_NAME = "DnsClient";

    private EventLoopGroup eventLoopGroup;

    private ChannelFactory<? extends DatagramChannel> channelFactory;

    private DnsCache resolveCache;
    private DnsCache authoritativeDnsServerCache;

    private int minTtl = 0;
    private int maxTtl = Integer.MAX_VALUE;
    private int negativeTtl = 0;
    private long queryTimeoutMillis = 5000;

    private ResolvedAddressTypes resolvedAddressTypes = DnsNameResolver.DEFAULT_RESOLVE_ADDRESS_TYPES;
    private boolean recursionDesired = true;
    private int maxQueriesPerResolve = 16;

    private boolean traceEnabled;
    private int maxPayloadSize = 4096;

    private DnsServerAddressStreamProvider dnsServerAddressStreamProvider = DefaultDnsServerAddressStreamProvider.INSTANCE;
    private DnsQueryLifecycleObserverFactory dnsQueryLifecycleObserverFactory = NoopDnsQueryLifecycleObserverFactory.INSTANCE;

    private String[] searchDomains;
    private int ndots = -1;
    private boolean decodeIdn = true;

    /**
     * Creates a new DNS client, with default name server addresses.
     */
    public
    DnsClient() {
        this(Dns.INSTANCE.getDefaultNameServers());
    }

    /**
     * Creates a new DNS client, using the provided server (default port 53) for DNS query resolution, with a cache that will obey the TTL of the response
     *
     * @param nameServerAddresses the server to receive your DNS questions.
     */
    public
    DnsClient(final String nameServerAddresses) {
        this(nameServerAddresses, 53);
    }

    /**
     * Creates a new DNS client, using the provided server and por tfor DNS query resolution, with a cache that will obey the TTL of the response
     *
     * @param nameServerAddresses the server to receive your DNS questions.
     */
    public
    DnsClient(final String nameServerAddresses, int port) {
        this(Collections.singletonList(new InetSocketAddress(nameServerAddresses, port)));
    }

    /**
     * Creates a new DNS client, using the provided server for DNS query resolution, with a cache that will obey the TTL of the response
     *
     * @param nameServerAddresses the server to receive your DNS questions.
     */
    public
    DnsClient(final InetSocketAddress nameServerAddresses) {
        this(Collections.singletonList(nameServerAddresses));
    }

    /**
     * Creates a new DNS client.
     *
     * The default TTL value is {@code 0} and {@link Integer#MAX_VALUE}, which practically tells this resolver to
     * respect the TTL from the DNS server.
     *
     * @param nameServerAddresses the list of servers to receive your DNS questions, until it succeeds
     */
    @SuppressWarnings("deprecation")
    public
    DnsClient(Collection<InetSocketAddress> nameServerAddresses) {
        super(DnsClient.class);

        if (OS.INSTANCE.isAndroid()) {
            // android ONLY supports OIO (not NIO)
            eventLoopGroup = new io.netty.channel.oio.OioEventLoopGroup(1, new NamedThreadFactory(THREAD_NAME + "-DNS", threadGroup));
            channelType = io.netty.channel.socket.oio.OioDatagramChannel.class;
        }
        else if (OS.INSTANCE.isLinux() && NativeLibrary.isAvailable()) {
            // epoll network stack is MUCH faster (but only on linux)
            eventLoopGroup = new io.netty.channel.epoll.EpollEventLoopGroup(1, new NamedThreadFactory(THREAD_NAME + "-DNS", threadGroup));
            channelType = io.netty.channel.epoll.EpollDatagramChannel.class;
        }
        else if (OS.INSTANCE.isMacOsX() && NativeLibrary.isAvailable()) {
            // KQueue network stack is MUCH faster (but only on macosx)
            eventLoopGroup = new io.netty.channel.kqueue.KQueueEventLoopGroup(1, new NamedThreadFactory(THREAD_NAME + "-DNS", threadGroup));
            channelType = io.netty.channel.kqueue.KQueueDatagramChannel.class;
        }
        else {
            eventLoopGroup = new io.netty.channel.nio.NioEventLoopGroup(1, new NamedThreadFactory(THREAD_NAME + "-DNS", threadGroup));
            channelType = io.netty.channel.socket.nio.NioDatagramChannel.class;
        }

        manageForShutdown(eventLoopGroup);

        if (nameServerAddresses != null) {
            this.dnsServerAddressStreamProvider = new SequentialDnsServerAddressStreamProvider(nameServerAddresses);
        }
    }

    /**
     * Sets the cache for resolution results.
     *
     * @param resolveCache the DNS resolution results cache
     *
     * @return {@code this}
     */
    public
    DnsClient resolveCache(DnsCache resolveCache) {
        this.resolveCache = resolveCache;
        return this;
    }

    /**
     * Set the factory used to generate objects which can observe individual DNS queries.
     *
     * @param lifecycleObserverFactory the factory used to generate objects which can observe individual DNS queries.
     *
     * @return {@code this}
     */
    public
    DnsClient dnsQueryLifecycleObserverFactory(DnsQueryLifecycleObserverFactory lifecycleObserverFactory) {
        if (lifecycleObserverFactory == null) {
            throw new NullPointerException("lifecycleObserverFactory");
        }

        this.dnsQueryLifecycleObserverFactory = lifecycleObserverFactory;
        return this;
    }

    /**
     * Sets the cache for authoritative NS servers
     *
     * @param authoritativeDnsServerCache the authoritative NS servers cache
     *
     * @return {@code this}
     */
    public
    DnsClient authoritativeDnsServerCache(DnsCache authoritativeDnsServerCache) {
        this.authoritativeDnsServerCache = authoritativeDnsServerCache;
        return this;
    }

    /**
     * Sets the minimum and maximum TTL of the cached DNS resource records (in seconds). If the TTL of the DNS
     * resource record returned by the DNS server is less than the minimum TTL or greater than the maximum TTL,
     * this resolver will ignore the TTL from the DNS server and use the minimum TTL or the maximum TTL instead
     * respectively.
     * The default value is {@code 0} and {@link Integer#MAX_VALUE}, which practically tells this resolver to
     * respect the TTL from the DNS server.
     *
     * @param minTtl the minimum TTL
     * @param maxTtl the maximum TTL
     *
     * @return {@code this}
     */
    public
    DnsClient ttl(int minTtl, int maxTtl) {
        this.maxTtl = maxTtl;
        this.minTtl = minTtl;
        return this;
    }

    /**
     * Sets the TTL of the cache for the failed DNS queries (in seconds).
     *
     * @param negativeTtl the TTL for failed cached queries
     *
     * @return {@code this}
     */
    public
    DnsClient negativeTtl(int negativeTtl) {
        this.negativeTtl = negativeTtl;
        return this;
    }

    /**
     * Sets the timeout of each DNS query performed by this resolver (in milliseconds).
     *
     * @param queryTimeoutMillis the query timeout
     *
     * @return {@code this}
     */
    public
    DnsClient queryTimeoutMillis(long queryTimeoutMillis) {
        this.queryTimeoutMillis = queryTimeoutMillis;
        return this;
    }

    /**
     * Sets the list of the protocol families of the address resolved.
     * You can use {@link DnsClient#computeResolvedAddressTypes(InternetProtocolFamily...)}
     * to get a {@link ResolvedAddressTypes} out of some {@link InternetProtocolFamily}s.
     *
     * @param resolvedAddressTypes the address types
     *
     * @return {@code this}
     */
    public
    DnsClient resolvedAddressTypes(ResolvedAddressTypes resolvedAddressTypes) {
        this.resolvedAddressTypes = resolvedAddressTypes;
        return this;
    }

    /**
     * Sets if this resolver has to send a DNS query with the RD (recursion desired) flag set.
     *
     * @param recursionDesired true if recursion is desired
     *
     * @return {@code this}
     */
    public
    DnsClient recursionDesired(boolean recursionDesired) {
        this.recursionDesired = recursionDesired;
        return this;
    }

    /**
     * Sets the maximum allowed number of DNS queries to send when resolving a host name.
     *
     * @param maxQueriesPerResolve the max number of queries
     *
     * @return {@code this}
     */
    public
    DnsClient maxQueriesPerResolve(int maxQueriesPerResolve) {
        this.maxQueriesPerResolve = maxQueriesPerResolve;
        return this;
    }

    /**
     * Sets if this resolver should generate the detailed trace information in an exception message so that
     * it is easier to understand the cause of resolution failure.
     *
     * @param traceEnabled true if trace is enabled
     *
     * @return {@code this}
     */
    public
    DnsClient traceEnabled(boolean traceEnabled) {
        this.traceEnabled = traceEnabled;
        return this;
    }

    /**
     * Sets the capacity of the datagram packet buffer (in bytes).  The default value is {@code 4096} bytes.
     *
     * @param maxPayloadSize the capacity of the datagram packet buffer
     *
     * @return {@code this}
     */
    public
    DnsClient maxPayloadSize(int maxPayloadSize) {
        this.maxPayloadSize = maxPayloadSize;
        return this;
    }

    /**
     * Set the {@link DnsServerAddressStreamProvider} which is used to determine which DNS server is used to resolve
     * each hostname.
     *
     * @return {@code this}
     */
    public
    DnsClient nameServerProvider(DnsServerAddressStreamProvider dnsServerAddressStreamProvider) {
        if (dnsServerAddressStreamProvider == null) {
            throw new NullPointerException("dnsServerAddressStreamProvider");
        }

        this.dnsServerAddressStreamProvider = dnsServerAddressStreamProvider;
        return this;
    }

    /**
     * Set the list of search domains of the resolver.
     *
     * @param searchDomains the search domains
     *
     * @return {@code this}
     */
    public
    DnsClient searchDomains(Iterable<String> searchDomains) {
        if (searchDomains == null) {
            throw new NullPointerException("searchDomains");
        }

        final List<String> list = new ArrayList<String>(4);

        for (String f : searchDomains) {
            if (f == null) {
                break;
            }

            // Avoid duplicate entries.
            if (list.contains(f)) {
                continue;
            }

            list.add(f);
        }

        this.searchDomains = list.toArray(new String[list.size()]);
        return this;
    }

    /**
     * Set the number of dots which must appear in a name before an initial absolute query is made.
     * The default value is {@code 1}.
     *
     * @param ndots the ndots value
     *
     * @return {@code this}
     */
    public
    DnsClient ndots(int ndots) {
        this.ndots = ndots;
        return this;
    }

    private
    DnsCache newCache() {
        return new DefaultDnsCache(minTtl, maxTtl, negativeTtl);
    }

    /**
     * Set if domain / host names should be decoded to unicode when received.
     * See <a href="https://tools.ietf.org/html/rfc3492">rfc3492</a>.
     *
     * @param decodeIdn if should get decoded
     *
     * @return {@code this}
     */
    public
    DnsClient decodeToUnicode(boolean decodeIdn) {
        this.decodeIdn = decodeIdn;
        return this;
    }


    /**
     * Compute a {@link ResolvedAddressTypes} from some {@link InternetProtocolFamily}s.
     * An empty input will return the default value, based on "java.net" System properties.
     * Valid inputs are (), (IPv4), (IPv6), (Ipv4, IPv6) and (IPv6, IPv4).
     *
     * @param internetProtocolFamilies a valid sequence of {@link InternetProtocolFamily}s
     *
     * @return a {@link ResolvedAddressTypes}
     */
    public static
    ResolvedAddressTypes computeResolvedAddressTypes(InternetProtocolFamily... internetProtocolFamilies) {
        if (internetProtocolFamilies == null || internetProtocolFamilies.length == 0) {
            return DnsNameResolver.DEFAULT_RESOLVE_ADDRESS_TYPES;
        }
        if (internetProtocolFamilies.length > 2) {
            throw new IllegalArgumentException("No more than 2 InternetProtocolFamilies");
        }

        switch (internetProtocolFamilies[0]) {
            case IPv4:
                return (internetProtocolFamilies.length >= 2 && internetProtocolFamilies[1] == InternetProtocolFamily.IPv6)
                       ? ResolvedAddressTypes.IPV4_PREFERRED
                       : ResolvedAddressTypes.IPV4_ONLY;
            case IPv6:
                return (internetProtocolFamilies.length >= 2 && internetProtocolFamilies[1] == InternetProtocolFamily.IPv4)
                       ? ResolvedAddressTypes.IPV6_PREFERRED
                       : ResolvedAddressTypes.IPV6_ONLY;
            default:
                throw new IllegalArgumentException("Couldn't resolve ResolvedAddressTypes from InternetProtocolFamily array");
        }
    }


    /**
     * Starts the DNS Name Resolver for the client, which will resolve DNS queries.
     */
    public
    DnsClient start() {
        ReflectiveChannelFactory<DatagramChannel> channelFactory = new ReflectiveChannelFactory<DatagramChannel>(channelType);

        // default support is IPV4
        if (this.resolvedAddressTypes == null) {
            this.resolvedAddressTypes = ResolvedAddressTypes.IPV4_ONLY;
        }

        if (resolveCache != null && (minTtl != 0 || maxTtl != Integer.MAX_VALUE || negativeTtl != 0)) {
            throw new IllegalStateException("resolveCache and TTLs are mutually exclusive");
        }

        if (authoritativeDnsServerCache != null && (minTtl != 0 || maxTtl != Integer.MAX_VALUE || negativeTtl != 0)) {
            throw new IllegalStateException("authoritativeDnsServerCache and TTLs are mutually exclusive");
        }

        DnsCache resolveCache = this.resolveCache != null ? this.resolveCache : newCache();
        DnsCache authoritativeDnsServerCache = this.authoritativeDnsServerCache != null ? this.authoritativeDnsServerCache : newCache();

        resolver = new DnsNameResolver(eventLoopGroup.next(),
                                       channelFactory,
                                       resolveCache,
                                       authoritativeDnsServerCache,
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
                                       decodeIdn);

        return this;
    }

    /**
     * Clears the DNS resolver cache
     */
    public
    void reset() {
        if (resolver == null) {
            start();
        }

        clearResolver();
    }

    private
    void clearResolver() {
        resolver.resolveCache()
                .clear();
    }

    @Override
    protected
    void stopExtraActions() {
        if (resolver != null) {
            clearResolver();

            resolver.close(); // also closes the UDP channel that DNS client uses
        }
    }


    /**
     * Resolves a specific hostname A/AAAA record with the default timeout of 5 seconds
     *
     * @param hostname the hostname, ie: google.com, that you want to resolve
     *
     * @return the list of resolved InetAddress or throws an exception if the hostname cannot be resolved
     * @throws UnknownHostException if the hostname cannot be resolved
     */
    public
    List<InetAddress> resolve(String hostname) throws UnknownHostException {
        return resolve(hostname, 5);
    }

    /**
     * Resolves a specific hostname A/AAAA record.
     *
     * @param hostname the hostname, ie: google.com, that you want to resolve
     * @param queryTimeoutSeconds the number of seconds to wait for host resolution
     *
     * @return the list of resolved InetAddress or throws an exception if the hostname cannot be resolved
     * @throws UnknownHostException if the hostname cannot be resolved
     */
    public
    List<InetAddress> resolve(String hostname, int queryTimeoutSeconds) throws UnknownHostException {
        if (hostname == null) {
            throw new UnknownHostException("Cannot submit query for an unknown host");
        }

        if (resolver == null) {
            start();
        }

        // use "resolve", since it handles A/AAAA records + redirects correctly
        final Future<List<InetAddress>> resolve = resolver.resolveAll(hostname);

        boolean finished = resolve.awaitUninterruptibly(queryTimeoutSeconds, TimeUnit.SECONDS);

        // now return whatever value we had
        if (finished && resolve.isSuccess() && resolve.isDone()) {
            try {
                List<InetAddress> now = resolve.getNow();
                return now;
            } catch (Exception e) {
                String msg = "Could not ask question to DNS server";
                logger.error(msg, e);
                throw new UnknownHostException(msg);
            }
        }

        String msg = "Could not ask question to DNS server for A/AAAA record: " + hostname;
        logger.error(msg);

        UnknownHostException cause = (UnknownHostException) resolve.cause();
        if (cause != null) {
            throw cause;
        }

        throw new UnknownHostException(msg);
    }

    /**
     * @return the DNS resolver used by the client. This is for more advanced functionality
     */
    public
    DnsNameResolver getResolver() {
        return resolver;
    }

    /**
     * Resolves a specific hostname record, of the specified type (PTR, MX, TXT, etc) with the default timeout of 5 seconds
     * <p/>
     * <p/>
     * Note: PTR queries absolutely MUST end in '.in-addr.arpa' in order for the DNS server to understand it.
     * -- because of this, we will automatically fix this in case that clients are unaware of this requirement
     * <p/>
     * <p/>
     * Note: A/AAAA queries absolutely MUST end in a '.' -- because of this we will automatically fix this in case that clients are
     * unaware of this requirement
     *
     * @param hostname the hostname, ie: google.com, that you want to resolve
     * @param type     the DnsRecordType you want to resolve (PTR, MX, TXT, etc)
     *
     * @return the DnsRecords or throws an exception if the hostname cannot be resolved
     *
     * @throws @throws UnknownHostException if the hostname cannot be resolved
     */
    @SuppressWarnings({"unchecked", "Duplicates"})
    public
    DnsRecord[] query(String hostname, final int type) throws UnknownHostException {
        return query(hostname, type, 5);
    }

    /**
     * Resolves a specific hostname record, of the specified type (PTR, MX, TXT, etc)
     * <p/>
     * <p/>
     * Note: PTR queries absolutely MUST end in '.in-addr.arpa' in order for the DNS server to understand it.
     * -- because of this, we will automatically fix this in case that clients are unaware of this requirement
     * <p/>
     * <p/>
     * Note: A/AAAA queries absolutely MUST end in a '.' -- because of this we will automatically fix this in case that clients are
     * unaware of this requirement
     *
     * @param hostname the hostname, ie: google.com, that you want to resolve
     * @param type     the DnsRecordType you want to resolve (PTR, MX, TXT, etc)
     * @param queryTimeoutSeconds the number of seconds to wait for host resolution
     *
     * @return the DnsRecords or throws an exception if the hostname cannot be resolved
     *
     * @throws @throws UnknownHostException if the hostname cannot be resolved
     */
    @SuppressWarnings({"unchecked", "Duplicates"})
    public
    DnsRecord[] query(String hostname, final int type, int queryTimeoutSeconds) throws UnknownHostException {
        if (hostname == null) {
            throw new UnknownHostException("Cannot submit query for an unknown host");
        }

        if (resolver == null) {
            start();
        }

        // we use our own resolvers
        DnsQuestion dnsMessage = DnsQuestion.newQuery(hostname, type, recursionDesired);

        return query(dnsMessage, queryTimeoutSeconds);
    }


    /**
     * Resolves a specific DnsQuestion
     * <p/>
     * <p/>
     * Note: PTR queries absolutely MUST end in '.in-addr.arpa' in order for the DNS server to understand it.
     * -- because of this, we will automatically fix this in case that clients are unaware of this requirement
     * <p/>
     * <p/>
     * Note: A/AAAA queries absolutely MUST end in a '.' -- because of this we will automatically fix this in case that clients are
     * unaware of this requirement
     *
     * @param queryTimeoutSeconds the number of seconds to wait for host resolution
     *
     * @return the DnsRecords or throws an exception if the hostname cannot be resolved
     *
     * @throws @throws UnknownHostException if the hostname cannot be resolved
     */
    public
    DnsRecord[] query(final DnsQuestion dnsMessage, final int queryTimeoutSeconds) throws UnknownHostException {
        int questionCount = dnsMessage.getHeader()
                                      .getCount(DnsSection.QUESTION);

        if (questionCount > 1) {
            throw new UnknownHostException("Cannot ask more than 1 question at a time! You tried to ask " + questionCount + " questions at once");
        }

        final int type = dnsMessage.getQuestion()
                                   .getType();

        final Future<DnsResponse> query = resolver.query(dnsMessage);
        boolean finished = query.awaitUninterruptibly(queryTimeoutSeconds, TimeUnit.SECONDS);

        // now return whatever value we had
        if (finished && query.isSuccess() && query.isDone()) {
            DnsResponse response = query.getNow();
            try {
                final int code = response.getHeader()
                                         .getRcode();
                if (code == DnsResponseCode.NOERROR) {
                    return response.getSectionArray(DnsSection.ANSWER);
                }

                String msg = "Could not ask question to DNS server: Error code " + code + " for type: " + type + " - " + DnsRecordType.string(type);
                logger.error(msg);

                throw new UnknownHostException(msg);
            } finally {
                response.release();
            }
        }

        String msg = "Could not ask question to DNS server for type: " + DnsRecordType.string(type);
        logger.error(msg);

        UnknownHostException cause = (UnknownHostException) query.cause();
        if (cause != null) {
            throw cause;
        }

        throw new UnknownHostException(msg);

    }
}

