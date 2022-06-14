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
 * Mailbox Record  - specifies a host containing a mailbox.
 *
 * @author Brian Wellington
 */
class MBRecord : SingleNameBase {
    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = MBRecord()

    /**
     * Gets the mailbox for the domain
     */
    val mailbox: Name
        get() = singleName

    /**
     * Creates a new MB Record with the given data
     *
     * @param mailbox The host containing the mailbox for the domain.
     */
    constructor(name: Name, dclass: Int, ttl: Long, mailbox: Name) : super(name, DnsRecordType.MB, dclass, ttl, mailbox, "mailbox") {
        this.additionalName = singleName
    }

    companion object {
        private const val serialVersionUID = 532349543479150419L
    }
}
