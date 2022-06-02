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

internal class SequentialDnsServerAddressStream(private val addresses: Array<InetSocketAddress>, private var i: Int) :
    DnsServerAddressStream {
    override fun next(): InetSocketAddress {
        var i = i
        val next = addresses[i]
        if (++i < addresses.size) {
            this.i = i
        } else {
            this.i = 0
        }
        return next
    }

    override fun size(): Int {
        return addresses.size
    }

    override fun duplicate(): SequentialDnsServerAddressStream {
        return SequentialDnsServerAddressStream(addresses, i)
    }

    override fun toString(): String {
        return toString("sequential", i, addresses)
    }

    companion object {
        @JvmStatic
        fun toString(type: String, index: Int, addresses: Array<InetSocketAddress>): String {
            val buf = StringBuilder(type.length + 2 + addresses.size * 16)
            buf.append(type).append("(index: ").append(index)
            buf.append(", addrs: (")
            for (a in addresses) {
                buf.append(a).append(", ")
            }
            buf.setLength(buf.length - 2)
            buf.append("))")
            return buf.toString()
        }
    }
}
