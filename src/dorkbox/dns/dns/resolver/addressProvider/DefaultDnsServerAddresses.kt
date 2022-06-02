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

internal abstract class DefaultDnsServerAddresses(type: String, protected val addresses: Array<InetSocketAddress>) : DnsServerAddresses() {
    private val strVal: String

    init {
        val buf = StringBuilder(type.length + 2 + addresses.size * 16)
        buf.append(type).append('(')
        for (a in addresses) {
            buf.append(a).append(", ")
        }
        buf.setLength(buf.length - 2)
        buf.append(')')
        strVal = buf.toString()
    }

    override fun toString(): String {
        return strVal
    }
}
