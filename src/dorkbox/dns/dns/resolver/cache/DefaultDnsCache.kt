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
import io.netty.util.internal.ObjectUtil
import io.netty.util.internal.PlatformDependent
import io.netty.util.internal.UnstableApi
import java.net.InetAddress
import java.util.concurrent.*

/**
 * Default implementation of [DnsCache], backed by a [ConcurrentMap].
 * If any additional [DnsRecord] is used, no caching takes place.
 */
@UnstableApi
class DefaultDnsCache @JvmOverloads constructor(minTtl: Int = 0, maxTtl: Int = Int.MAX_VALUE, negativeTtl: Int = 0) : DnsCache {
    private val resolveCache = PlatformDependent.newConcurrentHashMap<String, MutableList<DnsCacheEntry>>()
    private val minTtl: Int
    private val maxTtl: Int
    private val negativeTtl: Int
    /**
     * Create a cache.
     * @param minTtl the minimum TTL
     * @param maxTtl the maximum TTL
     * @param negativeTtl the TTL for failed queries
     */
    /**
     * Create a cache that respects the TTL returned by the DNS server
     * and doesn't cache negative responses.
     */
    init {
        this.minTtl = ObjectUtil.checkPositiveOrZero(minTtl, "minTtl")
        this.maxTtl = ObjectUtil.checkPositiveOrZero(maxTtl, "maxTtl")
        if (minTtl > maxTtl) {
            throw IllegalArgumentException(
                "minTtl: $minTtl, maxTtl: $maxTtl (expected: 0 <= minTtl <= maxTtl)"
            )
        }
        this.negativeTtl = ObjectUtil.checkPositiveOrZero(negativeTtl, "negativeTtl")
    }

    /**
     * Returns the minimum TTL of the cached DNS resource records (in seconds).
     *
     * @see .maxTtl
     */
    fun minTtl(): Int {
        return minTtl
    }

    /**
     * Returns the maximum TTL of the cached DNS resource records (in seconds).
     *
     * @see .minTtl
     */
    fun maxTtl(): Int {
        return maxTtl
    }

    /**
     * Returns the TTL of the cache for the failed DNS queries (in seconds). The default value is `0`, which
     * disables the cache for negative results.
     */
    fun negativeTtl(): Int {
        return negativeTtl
    }

    override fun clear() {
        val i: MutableIterator<Map.Entry<String?, List<DnsCacheEntry?>>> = resolveCache.entries.iterator()
        while (i.hasNext()) {
            val e = i.next()
            i.remove()
            cancelExpiration(e.value)
        }
    }

    override fun clear(hostname: String): Boolean {
        var removed = false
        val i: MutableIterator<Map.Entry<String?, List<DnsCacheEntry?>>> = resolveCache.entries.iterator()
        while (i.hasNext()) {
            val e = i.next()
            if ((e.key == hostname)) {
                i.remove()
                cancelExpiration(e.value)
                removed = true
            }
        }
        return removed
    }

    override fun get(hostname: String):MutableList<DnsCacheEntry>? {
        return resolveCache[hostname]
    }

    private fun cachedEntries(hostname: String): MutableList<DnsCacheEntry> {
        var oldEntries = resolveCache[hostname]
        val entries: MutableList<DnsCacheEntry>
        if (oldEntries == null) {
            val newEntries: MutableList<DnsCacheEntry> = ArrayList(8)
            oldEntries = resolveCache.putIfAbsent(hostname, newEntries)
            entries = oldEntries ?: newEntries
        } else {
            entries = oldEntries
        }
        return entries
    }

    override fun cache(hostname: String, address: InetAddress, originalTtl: Long, loop: EventLoop) {
        if (maxTtl == 0) {
            return
        }
        val ttl = Math.max(minTtl, Math.min(maxTtl.toLong(), originalTtl).toInt())
        val entries = cachedEntries(hostname)
        val e = DnsCacheEntry(hostname, address)
        synchronized(entries) {
            if (!entries.isEmpty()) {
                val firstEntry: DnsCacheEntry? = entries.get(0)
                if (firstEntry!!.cause() != null) {
                    assert(entries.size == 1)
                    firstEntry.cancelExpiration()
                    entries.clear()
                }
            }
            entries.add(e)
        }
        scheduleCacheExpiration(entries, e, ttl, loop)
    }

    override fun cache(hostname: String, cause: Throwable, loop: EventLoop) {
        if (negativeTtl == 0) {
            return
        }
        val entries = cachedEntries(hostname)
        val e = DnsCacheEntry(hostname, cause)
        synchronized(entries) {
            val numEntries: Int = entries.size
            for (i in 0 until numEntries) {
                entries[i].cancelExpiration()
            }
            entries.clear()
            entries.add(e)
        }
        scheduleCacheExpiration(entries, e, negativeTtl, loop)
    }

    private fun scheduleCacheExpiration(entries: MutableList<DnsCacheEntry>, e: DnsCacheEntry, ttl: Int, loop: EventLoop) {
        e.scheduleExpiration(loop, {
            synchronized(entries) {
                entries.remove(e)
                if (entries.isEmpty()) {
                    resolveCache.remove(e.hostname())
                }
            }
        }, ttl.toLong(), TimeUnit.SECONDS)
    }

    override fun toString(): String {
        return StringBuilder().append("DefaultDnsCache(minTtl=").append(minTtl).append(", maxTtl=").append(maxTtl).append(", negativeTtl=")
            .append(negativeTtl).append(", cached resolved hostname=").append(resolveCache.size).append(")").toString()
    }

    companion object {
        private fun cancelExpiration(entries: List<DnsCacheEntry?>) {
            val numEntries = entries.size
            for (i in 0 until numEntries) {
                entries[i]!!.cancelExpiration()
            }
        }
    }
}
