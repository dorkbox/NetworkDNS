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
package dorkbox.dns.dns.resolver.cache

import io.netty.channel.EventLoop
import io.netty.util.internal.UnstableApi
import java.net.InetAddress

/**
 * A cache for DNS resolution entries.
 */
@UnstableApi
interface DnsCache {
    /**
     * Clears all the resolved addresses cached by this resolver.
     *
     * @see .clear
     */
    fun clear()

    /**
     * Clears the resolved addresses of the specified host name from the cache of this resolver.
     *
     * @return `true` if and only if there was an entry for the specified host name in the cache and
     * it has been removed by this method
     */
    fun clear(hostname: String): Boolean

    /**
     * Return the cached entries for the given hostname.
     * @param hostname the hostname
     * @return the cached entries
     */
    operator fun get(hostname: String): MutableList<DnsCacheEntry>?

    /**
     * Cache a resolved address for a given hostname.
     * @param hostname the hostname
     * @param address the resolved address
     * @param originalTtl the TLL as returned by the DNS server
     * @param loop the [EventLoop] used to register the TTL timeout
     */
    fun cache(hostname: String, address: InetAddress, originalTtl: Long, loop: EventLoop)

    /**
     * Cache the resolution failure for a given hostname.
     * @param hostname the hostname
     * @param cause the resolution failure
     * @param loop the [EventLoop] used to register the TTL timeout
     */
    fun cache(hostname: String, cause: Throwable, loop: EventLoop)
}
