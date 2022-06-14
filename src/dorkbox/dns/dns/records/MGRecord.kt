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
 * Mail Group Record  - specifies a mailbox which is a member of a mail group.
 *
 * @author Brian Wellington
 */
class MGRecord : SingleNameBase {
    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = MGRecord()

    /**
     * Creates a new MG Record with the given data
     *
     * @param mailbox The mailbox that is a member of the group specified by the
     * domain.
     */
    constructor(name: Name, dclass: Int, ttl: Long, mailbox: Name) : super(name, DnsRecordType.MG, dclass, ttl, mailbox, "mailbox") {}

    /**
     * Gets the mailbox in the mail group specified by the domain
     */
    val mailbox: Name
        get() = singleName

    companion object {
        private const val serialVersionUID = -3980055550863644582L
    }
}
