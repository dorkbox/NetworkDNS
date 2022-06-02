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

import java.net.InetSocketAddress

internal class SingletonDnsServerAddresses(private val address: InetSocketAddress) : DnsServerAddresses() {
    private val stream: DnsServerAddressStream = object : DnsServerAddressStream {
        override fun next(): InetSocketAddress {
            return address
        }

        override fun size(): Int {
            return 1
        }

        override fun duplicate(): DnsServerAddressStream {
            return this
        }

        override fun toString(): String {
            return this@SingletonDnsServerAddresses.toString()
        }
    }

    override fun stream(): DnsServerAddressStream {
        return stream
    }

    override fun toString(): String {
        return "singleton($address)"
    }
}
