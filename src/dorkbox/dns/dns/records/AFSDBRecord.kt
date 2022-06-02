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
 * AFS Data Base Record - maps a domain name to the name of an AFS cell
 * database server.
 *
 * @author Brian Wellington
 */
class AFSDBRecord : U16NameBase {
    internal constructor() {}

    override val `object`: DnsRecord
        get() = AFSDBRecord()

    /**
     * Creates an AFSDB Record from the given data.
     *
     * @param subtype Indicates the type of service provided by the host.
     * @param host The host providing the service.
     */
    constructor(name: Name, dclass: Int, ttl: Long, subtype: Int, host: Name) : super(
        name,
        DnsRecordType.AFSDB,
        dclass,
        ttl,
        subtype,
        "subtype",
        host,
        "host"
    ) {
    }

    /**
     * Gets the subtype indicating the service provided by the host.
     */
    val subtype: Int
        get() = u16Field

    /**
     * Gets the host providing service for the domain.
     */
    val host: Name
        get() = nameField

    companion object {
        private const val serialVersionUID = 3034379930729102437L
    }
}
