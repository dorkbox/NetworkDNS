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

import static io.netty.util.internal.ObjectUtil.checkNotNull;

import dorkbox.dns.dns.records.DnsMessage;
import io.netty.util.internal.UnstableApi;

/**
 * Combines two {@link DnsQueryLifecycleObserverFactory} into a single {@link DnsQueryLifecycleObserverFactory}.
 */
@UnstableApi
public final
class BiDnsQueryLifecycleObserverFactory implements DnsQueryLifecycleObserverFactory {
    private final DnsQueryLifecycleObserverFactory a;
    private final DnsQueryLifecycleObserverFactory b;

    /**
     * Create a new instance.
     *
     * @param a The {@link DnsQueryLifecycleObserverFactory} that will receive events first.
     * @param b The {@link DnsQueryLifecycleObserverFactory} that will receive events second.
     */
    public
    BiDnsQueryLifecycleObserverFactory(DnsQueryLifecycleObserverFactory a, DnsQueryLifecycleObserverFactory b) {
        this.a = checkNotNull(a, "a");
        this.b = checkNotNull(b, "b");
    }

    @Override
    public
    DnsQueryLifecycleObserver newDnsQueryLifecycleObserver(DnsMessage question) {
        return new BiDnsQueryLifecycleObserver(a.newDnsQueryLifecycleObserver(question), b.newDnsQueryLifecycleObserver(question));
    }
}
