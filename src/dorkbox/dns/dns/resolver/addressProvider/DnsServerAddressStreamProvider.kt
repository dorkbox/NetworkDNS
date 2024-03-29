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

/**
 * Provides an opportunity to override which [DnsServerAddressStream] is used to resolve a specific hostname.
 *
 *
 * For example this can be used to represent [/etc/resolv.conf](https://linux.die.net/man/5/resolver) and
 * [
 * /etc/resolver](https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man5/resolver.5.html).
 */
interface DnsServerAddressStreamProvider {
    /**
     * Ask this provider for the name servers to query for `hostname`.
     *
     * @param hostname The hostname for which to lookup the DNS server addressed to use.
     * If this is the final [DnsServerAddressStreamProvider] to be queried then generally empty
     * string or `'.'` correspond to the default [DnsServerAddressStream].
     *
     * @return The [DnsServerAddressStream] which should be used to resolve `hostname`.
     */
    fun nameServerAddressStream(hostname: String): DnsServerAddressStream
}
