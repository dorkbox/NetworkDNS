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
 * DNAME Record  - maps a nonterminal alias (subtree) to a different domain
 *
 * @author Brian Wellington
 */
class DNAMERecord : SingleNameBase {
    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = DNAMERecord()

    /**
     * Creates a new DNAMERecord with the given data
     *
     * @param alias The name to which the DNAME alias points
     */
    constructor(name: Name, dclass: Int, ttl: Long, alias: Name) : super(name, DnsRecordType.DNAME, dclass, ttl, alias, "alias") {}

    /**
     * Gets the target of the DNAME Record
     */
    val target: Name
        get() = singleName

    /**
     * Gets the alias specified by the DNAME Record
     */
    val alias: Name
        get() = singleName

    companion object {
        private const val serialVersionUID = 2670767677200844154L
    }
}
