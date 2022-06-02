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

import dorkbox.dns.dns.Compression
import dorkbox.dns.dns.DnsOutput
import dorkbox.dns.dns.Name
import dorkbox.dns.dns.constants.DnsRecordType

/**
 * Mail Exchange - specifies where mail to a domain is sent
 *
 * @author Brian Wellington
 */
class MXRecord : U16NameBase {
    internal constructor() {}

    override val `object`: DnsRecord
        get() = MXRecord()


    /**
     * Returns the target of the MX record
     */
    val target: Name
        get() = nameField

    /**
     * Returns the priority of this MX record
     */
    val priority: Int
        get() = u16Field


    /**
     * Creates an MX Record from the given data
     *
     * @param priority The priority of this MX.  Records with lower priority are preferred.
     * @param target The host that mail is sent to
     */
    constructor(name: Name, dclass: Int, ttl: Long, priority: Int, target: Name) : super(
        name, DnsRecordType.MX, dclass, ttl, priority, "priority", target, "target"
    ) {
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeU16(u16Field)
        nameField.toWire(out, c, canonical)
    }

    companion object {
        private const val serialVersionUID = 2914841027584208546L
    }
}
