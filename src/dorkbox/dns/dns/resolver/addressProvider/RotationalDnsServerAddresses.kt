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
import java.util.concurrent.atomic.*

internal class RotationalDnsServerAddresses(addresses: Array<InetSocketAddress>) : DefaultDnsServerAddresses("rotational", addresses) {

    @Volatile
    private var startIdx = 0

    override fun stream(): DnsServerAddressStream {
        while (true) {
            val curStartIdx = startIdx
            var nextStartIdx = curStartIdx + 1
            if (nextStartIdx >= addresses.size) {
                nextStartIdx = 0
            }
            if (startIdxUpdater.compareAndSet(this, curStartIdx, nextStartIdx)) {
                return SequentialDnsServerAddressStream(addresses, curStartIdx)
            }
        }
    }

    companion object {
        private val startIdxUpdater = AtomicIntegerFieldUpdater.newUpdater(
            RotationalDnsServerAddresses::class.java, "startIdx"
        )
    }
}
