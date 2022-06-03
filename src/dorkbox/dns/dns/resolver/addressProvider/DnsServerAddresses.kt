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

import dorkbox.dns.dns.resolver.addressProvider.DefaultDnsServerAddressStreamProvider.Companion.defaultAddressArray
import java.net.InetSocketAddress

/**
 * Provides an infinite sequence of DNS server addresses to [DnsNameResolver].
 */
abstract class DnsServerAddresses {
    /**
     * Starts a new infinite stream of DNS server addresses. This method is invoked by [DnsNameResolver] on every
     * uncached [DnsNameResolver.resolve]or [DnsNameResolver.resolveAll].
     */
    abstract fun stream(): DnsServerAddressStream

    companion object {

        @Deprecated(
            """Use {@link DefaultDnsServerAddressStreamProvider#defaultAddressList()}.
              <p>
              Returns the list of the system DNS server addresses. If it failed to retrieve the list of the system DNS server
              addresses from the environment, it will return {@code '8.8.8.8'} and {@code '8.8.4.4'}, the addresses of the
              Google public DNS servers."""
        )
        fun defaultAddressList(): List<InetSocketAddress> {
            return DefaultDnsServerAddressStreamProvider.defaultAddressList()
        }

        @Deprecated(
            """Use {@link DefaultDnsServerAddressStreamProvider#defaultAddresses()}.
              <p>
              Returns the {@link DnsServerAddresses} that yields the system DNS server addresses sequentially. If it failed to
              retrieve the list of the system DNS server addresses from the environment, it will use {@code '8.8.8.8'} and
              {@code '8.8.4.4'}, the addresses of the Google public DNS servers.
              <p>
              This method has the same effect with the following code:
              <pre>
                      DnsServerAddresses.sequential(DnsServerAddresses.defaultAddressList());
                      </pre>
              </p>"""
        )
        fun defaultAddresses(): DnsServerAddresses {
            return DefaultDnsServerAddressStreamProvider.defaultAddresses()
        }

        /**
         * Returns the [DnsServerAddresses] that yields the specified `addresses` sequentially. Once the
         * last address is yielded, it will start again from the first address.
         */
        fun sequential(addresses: Iterable<InetSocketAddress>): DnsServerAddresses {
            return sequential0(*sanitize(addresses))
        }

        private fun sequential0(vararg addresses: InetSocketAddress): DnsServerAddresses {
            return if (addresses.size == 1) {
                singleton(addresses[0])
            } else object : DefaultDnsServerAddresses("sequential", addresses as Array<InetSocketAddress>) {
                override fun stream(): DnsServerAddressStream {
                    return SequentialDnsServerAddressStream(addresses as Array<InetSocketAddress>, 0)
                }
            }
        }

        /**
         * Returns the [DnsServerAddresses] that yields only a single `address`.
         */
        fun singleton(address: InetSocketAddress): DnsServerAddresses {
            require(!address.isUnresolved) { "cannot use an unresolved DNS server address: $address" }
            return SingletonDnsServerAddresses(address)
        }

        private fun sanitize(addresses: Iterable<InetSocketAddress>): Array<InetSocketAddress> {
            val list: MutableList<InetSocketAddress>
            list = if (addresses is Collection<*>) {
                ArrayList((addresses as Collection<*>).size)
            } else {
                ArrayList(4)
            }
            for (a in addresses) {
                require(!a.isUnresolved) { "cannot use an unresolved DNS server address: $a" }
                list.add(a)
            }
            require(list.isNotEmpty()) { "empty addresses" }
            return list.toTypedArray()
        }

        /**
         * Returns the [DnsServerAddresses] that yields the specified `addresses` sequentially. Once the
         * last address is yielded, it will start again from the first address.
         */
        fun sequential(vararg addresses: InetSocketAddress): DnsServerAddresses {
            return sequential0(*sanitize(addresses as Array<InetSocketAddress>))
        }

        private fun sanitize(addresses: Array<InetSocketAddress>): Array<InetSocketAddress> {
            val list: MutableList<InetSocketAddress> = ArrayList(addresses.size)
            for (a in addresses) {
                require(!a.isUnresolved) { "cannot use an unresolved DNS server address: $a" }
                list.add(a)
            }
            return if (list.isEmpty()) {
                defaultAddressArray()
            } else list.toTypedArray()
        }

        /**
         * Returns the [DnsServerAddresses] that yields the specified `address` in a shuffled order. Once all
         * addresses are yielded, the addresses are shuffled again.
         */
        fun shuffled(addresses: Iterable<InetSocketAddress>?): DnsServerAddresses {
            return shuffled0(sanitize(sanitize(addresses as Iterable<InetSocketAddress>)))
        }

        private fun shuffled0(addresses: Array<InetSocketAddress>): DnsServerAddresses {
            return if (addresses.size == 1) {
                singleton(addresses[0])
            } else object : DefaultDnsServerAddresses("shuffled", addresses) {
                override fun stream(): DnsServerAddressStream {
                    return ShuffledDnsServerAddressStream(addresses)
                }
            }
        }

        /**
         * Returns the [DnsServerAddresses] that yields the specified `addresses` in a shuffled order. Once all
         * addresses are yielded, the addresses are shuffled again.
         */
        fun shuffled(vararg addresses: InetSocketAddress): DnsServerAddresses {
            return shuffled0(sanitize(addresses as Array<InetSocketAddress>))
        }

        /**
         * Returns the [DnsServerAddresses] that yields the specified `addresses` in a rotational sequential
         * order. It is similar to [.sequential], but each [DnsServerAddressStream] starts from
         * a different starting point.  For example, the first [.stream] will start from the first address, the
         * second one will start from the second address, and so on.
         */
        fun rotational(addresses: Iterable<InetSocketAddress>): DnsServerAddresses {
            return rotational0(sanitize(addresses))
        }

        private fun rotational0(addresses: Array<InetSocketAddress>): DnsServerAddresses {
            return if (addresses.size == 1) {
                singleton(addresses[0])
            } else RotationalDnsServerAddresses(addresses)
        }

        /**
         * Returns the [DnsServerAddresses] that yields the specified `addresses` in a rotational sequential
         * order. It is similar to [.sequential], but each [DnsServerAddressStream] starts from
         * a different starting point.  For example, the first [.stream] will start from the first address, the
         * second one will start from the second address, and so on.
         */
        fun rotational(vararg addresses: InetSocketAddress): DnsServerAddresses {
            return rotational0(sanitize(addresses as Array<InetSocketAddress>))
        }
    }
}
