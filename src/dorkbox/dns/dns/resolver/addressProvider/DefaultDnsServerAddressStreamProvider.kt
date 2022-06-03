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
package dorkbox.dns.dns.resolver.addressProvider

import dorkbox.netUtil.Dns.defaultNameServers
import java.net.InetSocketAddress

/**
 * A [DnsServerAddressStreamProvider] which will use predefined default DNS servers to use for DNS resolution.
 * These defaults do not respect your host's machines defaults.
 *
 *
 * This may use the JDK's blocking DNS resolution to bootstrap the default DNS server addresses.
 */
class DefaultDnsServerAddressStreamProvider private constructor() : DnsServerAddressStreamProvider {
    override fun nameServerAddressStream(hostname: String): DnsServerAddressStream {
        return DEFAULT_NAME_SERVERS.stream()
    }

    companion object {
        val INSTANCE = DefaultDnsServerAddressStreamProvider()
        const val DNS_PORT = 53

        private val DEFAULT_NAME_SERVER_LIST: List<InetSocketAddress>
        private val DEFAULT_NAME_SERVER_ARRAY: Array<InetSocketAddress>
        private val DEFAULT_NAME_SERVERS: DnsServerAddresses

        init {
            val defaultNameServers = defaultNameServers
            DEFAULT_NAME_SERVER_LIST = defaultNameServers
            DEFAULT_NAME_SERVER_ARRAY = defaultNameServers.toTypedArray()
            DEFAULT_NAME_SERVERS = DnsServerAddresses.sequential(*DEFAULT_NAME_SERVER_ARRAY)
        }

        /**
         * Returns the list of the system DNS server addresses. If it failed to retrieve the list of the system DNS server
         * addresses from the environment, it will return `"8.8.8.8"` and `"8.8.4.4"`, the addresses of the
         * Google public DNS servers.
         */
        fun defaultAddressList(): List<InetSocketAddress> {
            return DEFAULT_NAME_SERVER_LIST
        }

        /**
         * Returns the [DnsServerAddresses] that yields the system DNS server addresses sequentially. If it failed to
         * retrieve the list of the system DNS server addresses from the environment, it will use `"8.8.8.8"` and
         * `"8.8.4.4"`, the addresses of the Google public DNS servers.
         *
         *
         * This method has the same effect with the following code:
         * <pre>
         * DnsServerAddresses.sequential(DnsServerAddresses.defaultAddressList());
        </pre> *
         *
         */
        fun defaultAddresses(): DnsServerAddresses {
            return DEFAULT_NAME_SERVERS
        }

        /**
         * Get the array form of [.defaultAddressList].
         *
         * @return The array form of [.defaultAddressList].
         */
        fun defaultAddressArray(): Array<InetSocketAddress> {
            return DEFAULT_NAME_SERVER_ARRAY.clone()
        }
    }
}
