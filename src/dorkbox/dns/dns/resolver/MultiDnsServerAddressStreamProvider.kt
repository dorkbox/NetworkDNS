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
import dorkbox.dns.dns.resolver.addressProvider.DnsServerAddressStreamProvider
import io.netty.util.internal.UnstableApi

/**
 * A [DnsServerAddressStreamProvider] which iterates through a collection of
 * [DnsServerAddressStreamProvider] until the first non-`null` result is found.
 */
@UnstableApi
class MultiDnsServerAddressStreamProvider : DnsServerAddressStreamProvider {
    private val providers: Array<DnsServerAddressStreamProvider>

    /**
     * Create a new instance.
     *
     * @param providers The providers to use for DNS resolution. They will be queried in order.
     */
    constructor(providers: List<DnsServerAddressStreamProvider>) {
        this.providers = providers.toTypedArray()
    }

    /**
     * Create a new instance.
     *
     * @param providers The providers to use for DNS resolution. They will be queried in order.
     */
    constructor(vararg providers: DnsServerAddressStreamProvider) {
        this.providers = providers.clone() as Array<DnsServerAddressStreamProvider>
    }

    override fun nameServerAddressStream(hostname: String): DnsServerAddressStream {
        for (provider in providers) {
            return provider.nameServerAddressStream(hostname)
        }

        throw IllegalStateException("No name servers provided.")
    }
}
