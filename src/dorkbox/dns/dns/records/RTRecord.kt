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
 * Route Through Record - lists a route preference and intermediate host.
 *
 * @author Brian Wellington
 */
class RTRecord : U16NameBase {
    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = RTRecord()

    /**
     * Gets the preference of the route.
     */
    val preference: Int
        get() = u16Field

    /**
     * Gets the host to use as a router.
     */
    val intermediateHost: Name
        get() = nameField

    /**
     * Creates an RT Record from the given data
     *
     * @param preference The preference of the route.  Smaller numbers indicate
     * more preferred routes.
     * @param intermediateHost The domain name of the host to use as a router.
     */
    constructor(name: Name, dclass: Int, ttl: Long, preference: Int, intermediateHost: Name) : super(
        name, DnsRecordType.RT, dclass, ttl, preference, "preference", intermediateHost, "intermediateHost"
    )

    companion object {
        private const val serialVersionUID = -3206215651648278098L
    }
}
