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
package dorkbox.dns.dns.resolver.addressProvider

import io.netty.util.internal.ObjectUtil

/**
 * A [DnsServerAddressStreamProvider] which is backed by a single [DnsServerAddresses].
 */
abstract class UniSequentialDnsServerAddressStreamProvider(addresses: DnsServerAddresses) : DnsServerAddressStreamProvider {
    private val addresses: DnsServerAddresses

    init {
        this.addresses = ObjectUtil.checkNotNull(addresses, "addresses")
    }

    override fun nameServerAddressStream(hostname: String): DnsServerAddressStream {
        return addresses.stream()
    }
}
