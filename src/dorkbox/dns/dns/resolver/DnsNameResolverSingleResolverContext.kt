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

import dorkbox.dns.dns.resolver.addressProvider.DnsServerAddressStream
import dorkbox.dns.dns.resolver.cache.DnsCache
import dorkbox.dns.dns.resolver.cache.DnsCacheEntry
import io.netty.util.concurrent.Promise
import java.net.InetAddress

/**
 *
 */
internal class DnsNameResolverSingleResolverContext(parent: DnsNameResolver, hostname: String, resolveCache: DnsCache, nameServerAddrs: DnsServerAddressStream) : DnsNameResolverContext<InetAddress>(parent, hostname, resolveCache, nameServerAddrs) {
    override fun finishResolve(
        addressType: Class<out InetAddress>,
        resolvedEntries: List<DnsCacheEntry>,
        promise: Promise<InetAddress>
    ): Boolean {
        val numEntries = resolvedEntries.size
        for (i in 0 until numEntries) {
            val a = resolvedEntries[i].address()
            if (addressType.isInstance(a)) {
                DnsNameResolver.trySuccess(promise, a!!)
                return true
            }
        }
        return false
    }

    override fun newResolverContext(parent: DnsNameResolver, hostname: String, resolveCache: DnsCache, nameServerAddrs: DnsServerAddressStream): DnsNameResolverContext<InetAddress> {
        return DnsNameResolverSingleResolverContext(parent, hostname, resolveCache, nameServerAddrs)
    }
}
