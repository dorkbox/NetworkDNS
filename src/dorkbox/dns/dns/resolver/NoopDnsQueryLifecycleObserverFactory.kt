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

import dorkbox.dns.dns.records.DnsMessage;
import io.netty.util.internal.UnstableApi;

@UnstableApi
public final
class NoopDnsQueryLifecycleObserverFactory implements DnsQueryLifecycleObserverFactory {
    public static final NoopDnsQueryLifecycleObserverFactory INSTANCE = new NoopDnsQueryLifecycleObserverFactory();

    private
    NoopDnsQueryLifecycleObserverFactory() {
    }

    @Override
    public
    DnsQueryLifecycleObserver newDnsQueryLifecycleObserver(DnsMessage question) {
        return NoopDnsQueryLifecycleObserver.INSTANCE;
    }
}
