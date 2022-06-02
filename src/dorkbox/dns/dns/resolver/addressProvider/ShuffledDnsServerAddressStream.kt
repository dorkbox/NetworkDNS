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

import dorkbox.dns.dns.resolver.addressProvider.SequentialDnsServerAddressStream.Companion.toString
import io.netty.util.internal.PlatformDependent
import java.net.InetSocketAddress

internal class ShuffledDnsServerAddressStream : DnsServerAddressStream {
    private val addresses: Array<InetSocketAddress>
    private var i = 0

    /**
     * Create a new instance.
     *
     * @param addresses The addresses are not cloned. It is assumed the caller has cloned this array or otherwise will
     * not modify the contents.
     */
    constructor(addresses: Array<InetSocketAddress>) {
        this.addresses = addresses
        shuffle()
    }

    private fun shuffle() {
        val addresses = addresses
        val r = PlatformDependent.threadLocalRandom()

        for (i in addresses.indices.reversed()) {
            val tmp = addresses[i]
            val j = r.nextInt(i + 1)
            addresses[i] = addresses[j]
            addresses[j] = tmp
        }
    }

    private constructor(addresses: Array<InetSocketAddress>, startIdx: Int) {
        this.addresses = addresses
        i = startIdx
    }

    override fun next(): InetSocketAddress {
        var i = i
        val next = addresses[i]
        if (++i < addresses.size) {
            this.i = i
        } else {
            this.i = 0
            shuffle()
        }
        return next
    }

    override fun size(): Int {
        return addresses.size
    }

    override fun duplicate(): ShuffledDnsServerAddressStream {
        return ShuffledDnsServerAddressStream(addresses, i)
    }

    override fun toString(): String {
        return toString("shuffled", i, addresses)
    }
}
