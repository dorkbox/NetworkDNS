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
 * Mail Destination Record  - specifies a mail agent which delivers mail
 * for a domain (obsolete)
 *
 * @author Brian Wellington
 */
@Deprecated("")
class MDRecord : SingleNameBase {
    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = MDRecord()

    /**
     * Creates a new MD Record with the given data
     *
     * @param mailAgent The mail agent that delivers mail for the domain.
     */
    constructor(name: Name, dclass: Int, ttl: Long, mailAgent: Name) : super(
        name,
        DnsRecordType.MD,
        dclass,
        ttl,
        mailAgent,
        "mail agent"
    ) {
        additionalName = singleName
    }

    /**
     * Gets the mail agent for the domain
     */
    val mailAgent: Name
        get() = singleName

    companion object {
        private const val serialVersionUID = 5268878603762942202L
    }
}
