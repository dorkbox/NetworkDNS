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
 * A noop DNS cache that actually never caches anything.
 */
@UnstableApi
class NoopDnsCache
/**
 * Private singleton constructor.
 */
private constructor() : DnsCache {
    override fun clear() {}
    override fun clear(hostname: String): Boolean {
        return false
    }

    override fun get(hostname: String): MutableList<DnsCacheEntry>? {
        return mutableListOf<DnsCacheEntry>()
    }

    override fun cache(hostname: String, address: InetAddress, originalTtl: Long, loop: EventLoop) {}
    override fun cache(hostname: String, cause: Throwable, loop: EventLoop) {}
    override fun toString(): String {
        return NoopDnsCache::class.java.simpleName
    }

    companion object {
        val INSTANCE = NoopDnsCache()
    }
}
