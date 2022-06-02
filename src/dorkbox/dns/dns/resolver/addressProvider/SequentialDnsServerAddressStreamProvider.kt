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

import dorkbox.dns.dns.resolver.addressProvider.DnsServerAddresses.Companion.sequential
import java.net.InetSocketAddress

/**
 * A [DnsServerAddressStreamProvider] which is backed by a sequential list of DNS servers.
 */
class SequentialDnsServerAddressStreamProvider : UniSequentialDnsServerAddressStreamProvider {
    /**
     * Create a new instance.
     *
     * @param addresses The addresses which will be be returned in sequential order via
     * [.nameServerAddressStream]
     */
    constructor(vararg addresses: InetSocketAddress?) : super(sequential(*addresses as Array<out InetSocketAddress>)) {}

    /**
     * Create a new instance.
     *
     * @param addresses The addresses which will be be returned in sequential order via
     * [.nameServerAddressStream]
     */
    constructor(addresses: Iterable<InetSocketAddress?>?) : super(sequential(addresses as Iterable<InetSocketAddress>)) {}
}
