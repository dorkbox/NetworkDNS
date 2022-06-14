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
 * Mail Forwarder Record  - specifies a mail agent which forwards mail
 * for a domain (obsolete)
 *
 * @author Brian Wellington
 */
@Deprecated("")
class MFRecord : SingleNameBase {
    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = MFRecord()

    /**
     * Gets the mail agent for the domain
     */
    val mailAgent: Name
        get() = singleName

    /**
     * Creates a new MF Record with the given data
     *
     * @param mailAgent The mail agent that forwards mail for the domain.
     */
    constructor(name: Name, dclass: Int, ttl: Long, mailAgent: Name) : super(
        name,
        DnsRecordType.MF,
        dclass,
        ttl,
        mailAgent,
        "mail agent"
    ) {
        this.additionalName = singleName
    }

    companion object {
        private const val serialVersionUID = -6670449036843028169L
    }
}
