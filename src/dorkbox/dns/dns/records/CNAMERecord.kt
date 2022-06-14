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
 * CNAME Record  - maps an alias to its real name
 *
 * @author Brian Wellington
 */
class CNAMERecord : SingleCompressedNameBase {
    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = CNAMERecord()

    /**
     * Gets the target of the CNAME Record
     */
    val target: Name
        get() = singleName


    /**
     * Gets the alias specified by the CNAME Record
     */
    val alias: Name
        get() = singleName

    /**
     * Creates a new CNAMERecord with the given data
     *
     * @param alias The name to which the CNAME alias points
     */
    constructor(name: Name, dclass: Int, ttl: Long, alias: Name) : super(name, DnsRecordType.CNAME, dclass, ttl, alias, "alias") {}

    companion object {
        private const val serialVersionUID = -4020373886892538580L
    }
}
