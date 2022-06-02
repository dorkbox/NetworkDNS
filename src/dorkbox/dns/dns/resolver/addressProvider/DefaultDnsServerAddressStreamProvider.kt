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
package dorkbox.dns.dns.resolver.addressProvider;

import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import dorkbox.netUtil.Dns;

/**
 * A {@link DnsServerAddressStreamProvider} which will use predefined default DNS servers to use for DNS resolution.
 * These defaults do not respect your host's machines defaults.
 * <p>
 * This may use the JDK's blocking DNS resolution to bootstrap the default DNS server addresses.
 */
public final
class DefaultDnsServerAddressStreamProvider implements DnsServerAddressStreamProvider {

    public static final DefaultDnsServerAddressStreamProvider INSTANCE = new DefaultDnsServerAddressStreamProvider();
    public static final int DNS_PORT = 53;
    private static final Logger logger = LoggerFactory.getLogger(DefaultDnsServerAddressStreamProvider.class);
    private static final List<InetSocketAddress> DEFAULT_NAME_SERVER_LIST;
    private static final InetSocketAddress[] DEFAULT_NAME_SERVER_ARRAY;
    private static final DnsServerAddresses DEFAULT_NAME_SERVERS;

    static {
        final List<InetSocketAddress> defaultNameServers = Dns.INSTANCE.getDefaultNameServers();

        DEFAULT_NAME_SERVER_LIST = Collections.unmodifiableList(defaultNameServers);
        DEFAULT_NAME_SERVER_ARRAY = defaultNameServers.toArray(new InetSocketAddress[0]);
        DEFAULT_NAME_SERVERS = DnsServerAddresses.sequential(DEFAULT_NAME_SERVER_ARRAY);
    }

    /**
     * Returns the list of the system DNS server addresses. If it failed to retrieve the list of the system DNS server
     * addresses from the environment, it will return {@code "8.8.8.8"} and {@code "8.8.4.4"}, the addresses of the
     * Google public DNS servers.
     */
    public static
    List<InetSocketAddress> defaultAddressList() {
        return DEFAULT_NAME_SERVER_LIST;
    }

    /**
     * Returns the {@link DnsServerAddresses} that yields the system DNS server addresses sequentially. If it failed to
     * retrieve the list of the system DNS server addresses from the environment, it will use {@code "8.8.8.8"} and
     * {@code "8.8.4.4"}, the addresses of the Google public DNS servers.
     * <p>
     * This method has the same effect with the following code:
     * <pre>
     * DnsServerAddresses.sequential(DnsServerAddresses.defaultAddressList());
     * </pre>
     * </p>
     */
    public static
    DnsServerAddresses defaultAddresses() {
        return DEFAULT_NAME_SERVERS;
    }

    /**
     * Get the array form of {@link #defaultAddressList()}.
     *
     * @return The array form of {@link #defaultAddressList()}.
     */
    static
    InetSocketAddress[] defaultAddressArray() {
        return DEFAULT_NAME_SERVER_ARRAY.clone();
    }

    private
    DefaultDnsServerAddressStreamProvider() {
    }

    @Override
    public
    DnsServerAddressStream nameServerAddressStream(String hostname) {
        return DEFAULT_NAME_SERVERS.stream();
    }
}
