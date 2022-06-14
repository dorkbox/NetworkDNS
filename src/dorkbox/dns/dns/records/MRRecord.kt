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
 * Mailbox Rename Record  - specifies a rename of a mailbox.
 *
 * @author Brian Wellington
 */
class MRRecord : SingleNameBase {
    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = MRRecord()


    /**
     * Gets the new name of the mailbox specified by the domain
     */
    val newName: Name
        get() = singleName
    
    /**
     * Creates a new MR Record with the given data
     *
     * @param newName The new name of the mailbox specified by the domain.
     * domain.
     */
    constructor(name: Name, dclass: Int, ttl: Long, newName: Name) : super(
        name,
        DnsRecordType.MR,
        dclass,
        ttl,
        newName,
        "new name"
    ) {
    }

    companion object {
        private const val serialVersionUID = -5617939094209927533L
    }
}
