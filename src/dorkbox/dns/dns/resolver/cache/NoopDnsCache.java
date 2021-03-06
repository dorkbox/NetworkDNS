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
package dorkbox.dns.dns.resolver.cache;

import java.net.InetAddress;
import java.util.Collections;
import java.util.List;

import io.netty.channel.EventLoop;
import io.netty.util.internal.UnstableApi;

/**
 * A noop DNS cache that actually never caches anything.
 */
@UnstableApi
public final class NoopDnsCache implements DnsCache {

    public static final NoopDnsCache INSTANCE = new NoopDnsCache();

    /**
     * Private singleton constructor.
     */
    private NoopDnsCache() {
    }

    @Override
    public void clear() {
    }

    @Override
    public boolean clear(String hostname) {
        return false;
    }

    @Override
    public List<DnsCacheEntry> get(String hostname) {
        return Collections.emptyList();
    }

    @Override
    public void cache(String hostname, InetAddress address, long originalTtl, EventLoop loop) {
    }

    @Override
    public void cache(String hostname, Throwable cause, EventLoop loop) {
    }

    @Override
    public String toString() {
        return NoopDnsCache.class.getSimpleName();
    }
}
