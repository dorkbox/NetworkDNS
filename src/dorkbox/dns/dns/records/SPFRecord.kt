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
package dorkbox.dns.dns.records

import dorkbox.dns.dns.Name
import dorkbox.dns.dns.constants.DnsRecordType

/**
 * Sender Policy Framework (RFC 4408, experimental)
 *
 * @author Brian Wellington
 */
class SPFRecord : TXTBase {
    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = SPFRecord()

    /**
     * Creates a SPF Record from the given data
     *
     * @param strings The text strings
     *
     * @throws IllegalArgumentException One of the strings has invalid escapes
     */
    constructor(name: Name, dclass: Int, ttl: Long, strings: List<String>) : super(name, DnsRecordType.SPF, dclass, ttl, strings)

    /**
     * Creates a SPF Record from the given data
     *
     * @param string One text string
     *
     * @throws IllegalArgumentException The string has invalid escapes
     */
    constructor(name: Name, dclass: Int, ttl: Long, string: String) : super(name, DnsRecordType.SPF, dclass, ttl, string)

    companion object {
        private const val serialVersionUID = -2100754352801658722L
    }
}
