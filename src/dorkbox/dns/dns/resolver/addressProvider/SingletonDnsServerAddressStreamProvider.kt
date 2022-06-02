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

import dorkbox.dns.dns.resolver.addressProvider.DnsServerAddresses.Companion.singleton
import java.net.InetSocketAddress

/**
 * A [DnsServerAddressStreamProvider] which always uses a single DNS server for resolution.
 */
class SingletonDnsServerAddressStreamProvider(
    /**
     * Create a new instance.
     *
     * @param address The singleton address to use for every DNS resolution.
     */
    address: InetSocketAddress) : UniSequentialDnsServerAddressStreamProvider(singleton(address))
