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

import java.net.InetSocketAddress

/**
 * An infinite stream of DNS server addresses.
 */
interface DnsServerAddressStream {
    /**
     * Retrieves the next DNS server address from the stream.
     */
    operator fun next(): InetSocketAddress

    /**
     * Get the number of times [.next] will return a distinct element before repeating or terminating.
     *
     * @return the number of times [.next] will return a distinct element before repeating or terminating.
     */
    fun size(): Int

    /**
     * Duplicate this object. The result of this should be able to be independently iterated over via [.next].
     *
     *
     * Note that [.clone] isn't used because it may make sense for some implementations to have the following
     * relationship `x.duplicate() == x`.
     *
     * @return A duplicate of this object.
     */
    fun duplicate(): DnsServerAddressStream
}
