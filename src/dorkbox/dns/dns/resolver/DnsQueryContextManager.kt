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

import dorkbox.netUtil.IPv4
import dorkbox.netUtil.IPv6
import io.netty.util.collection.IntObjectHashMap
import io.netty.util.collection.IntObjectMap
import io.netty.util.internal.PlatformDependent
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.UnknownHostException

internal class DnsQueryContextManager {
    /**
     * A map whose key is the DNS server address and value is the map of the DNS query ID and its corresponding [DnsQueryContext].
     */
    val map: MutableMap<InetSocketAddress, IntObjectMap<DnsQueryContext>> = HashMap()

    fun add(queryContext: DnsQueryContext): Int {
        val contexts = getOrCreateContextMap(queryContext.nameServerAddr())
        var id = PlatformDependent.threadLocalRandom().nextInt(65536 - 1) + 1
        val maxTries = 65535 shl 1
        var tries = 0

        synchronized(contexts) {
            while (true) {
                if (!contexts.containsKey(id)) {
                    contexts.put(id, queryContext)
                    return id
                }
                id = id + 1 and 0xFFFF
                check(++tries < maxTries) { "query ID space exhausted: " + queryContext.question() }
            }
        }
    }

    private fun getOrCreateContextMap(nameServerAddr: InetSocketAddress): IntObjectMap<DnsQueryContext> {
        synchronized(map) {
            val contexts = map[nameServerAddr]
            if (contexts != null) {
                return contexts
            }

            val newContexts: IntObjectMap<DnsQueryContext> = IntObjectHashMap()
            val a = nameServerAddr.address
            val port = nameServerAddr.port
            map[nameServerAddr] = newContexts

            if (a is Inet4Address) {
                // Also add the mapping for the IPv4-compatible IPv6 address.
                if (a.isLoopbackAddress) {
                    map[InetSocketAddress(IPv6.LOCALHOST, port)] = newContexts
                } else {
                    map[InetSocketAddress(toCompactAddress(a), port)] = newContexts
                }
            } else if (a is Inet6Address) {
                // Also add the mapping for the IPv4 address if this IPv6 address is compatible.
                if (a.isLoopbackAddress) {
                    map[InetSocketAddress(IPv4.LOCALHOST, port)] = newContexts
                } else if (a.isIPv4CompatibleAddress) {
                    map[InetSocketAddress(toIPv4Address(a), port)] = newContexts
                }
            }
            return newContexts
        }
    }

    operator fun get(nameServerAddr: InetSocketAddress, id: Int): DnsQueryContext? {
        val contexts = getContextMap(nameServerAddr)
        val qCtx: DnsQueryContext?
        if (contexts != null) {
            synchronized(contexts) { qCtx = contexts[id] }
        } else {
            qCtx = null
        }
        return qCtx
    }

    private fun getContextMap(nameServerAddr: InetSocketAddress): IntObjectMap<DnsQueryContext>? {
        synchronized(map) { return map[nameServerAddr] }
    }

    fun remove(nameServerAddr: InetSocketAddress, id: Int): DnsQueryContext? {
        val contexts = getContextMap(nameServerAddr) ?: return null
        synchronized(contexts) { return contexts.remove(id) }
    }

    companion object {
        private fun toCompactAddress(a4: Inet4Address): Inet6Address {
            val b4 = a4.address
            val b6 = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, b4[0], b4[1], b4[2], b4[3])

            return try {
                InetAddress.getByAddress(b6) as Inet6Address
            } catch (e: UnknownHostException) {
                throw Error(e)
            }
        }

        private fun toIPv4Address(a6: Inet6Address): Inet4Address {
            val b6 = a6.address
            val b4 = byteArrayOf(b6[12], b6[13], b6[14], b6[15])

            return try {
                InetAddress.getByAddress(b4) as Inet4Address
            } catch (e: UnknownHostException) {
                throw Error(e)
            }
        }
    }
}
