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

import dorkbox.dns.dns.records.DnsMessage
import io.netty.util.internal.ObjectUtil
import io.netty.util.internal.UnstableApi

/**
 * Combines two [DnsQueryLifecycleObserverFactory] into a single [DnsQueryLifecycleObserverFactory].
 */
@UnstableApi
class BiDnsQueryLifecycleObserverFactory(a: DnsQueryLifecycleObserverFactory, b: DnsQueryLifecycleObserverFactory) :
    DnsQueryLifecycleObserverFactory {
    private val a: DnsQueryLifecycleObserverFactory
    private val b: DnsQueryLifecycleObserverFactory

    /**
     * Create a new instance.
     *
     * @param a The [DnsQueryLifecycleObserverFactory] that will receive events first.
     * @param b The [DnsQueryLifecycleObserverFactory] that will receive events second.
     */
    init {
        this.a = ObjectUtil.checkNotNull(a, "a")
        this.b = ObjectUtil.checkNotNull(b, "b")
    }

    override fun newDnsQueryLifecycleObserver(question: DnsMessage): DnsQueryLifecycleObserver {
        return BiDnsQueryLifecycleObserver(a.newDnsQueryLifecycleObserver(question), b.newDnsQueryLifecycleObserver(question))
    }
}
