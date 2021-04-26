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
package dorkbox.dns.dns.resolver;

import java.net.InetAddress;
import java.util.List;

import dorkbox.dns.dns.resolver.addressProvider.DnsServerAddressStream;
import dorkbox.dns.dns.resolver.cache.DnsCache;
import dorkbox.dns.dns.resolver.cache.DnsCacheEntry;
import io.netty.util.concurrent.Promise;

/**
 *
 */
@SuppressWarnings("ForLoopReplaceableByForEach")
final
class DnsNameResolverSingleResolverContext extends DnsNameResolverContext<InetAddress> {
    DnsNameResolverSingleResolverContext(DnsNameResolver parent,
                                         String hostname,
                                         DnsCache resolveCache,
                                         DnsServerAddressStream nameServerAddrs) {
        super(parent, hostname, resolveCache, nameServerAddrs);
    }

    @Override
    boolean finishResolve(Class<? extends InetAddress> addressType, List<DnsCacheEntry> resolvedEntries, Promise<InetAddress> promise) {

        final int numEntries = resolvedEntries.size();

        for (int i = 0; i < numEntries; i++) {
            final InetAddress a = resolvedEntries.get(i).address();
            if (addressType.isInstance(a)) {
                DnsNameResolver.trySuccess(promise, a);
                return true;
            }
        }

        return false;
    }

    @Override
    DnsNameResolverContext<InetAddress> newResolverContext(DnsNameResolver parent,
                                                           String hostname,
                                                           DnsCache resolveCache,
                                                           DnsServerAddressStream nameServerAddrs) {
        return new DnsNameResolverSingleResolverContext(parent, hostname, resolveCache, nameServerAddrs);
    }
}
