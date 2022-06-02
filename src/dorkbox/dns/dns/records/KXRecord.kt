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
 * Key Exchange - delegation of authority
 *
 * @author Brian Wellington
 */
class KXRecord : U16NameBase {
    internal constructor() {}

    /**
     * Returns the preference of this KX record
     */
    open var preference = 0

    /**
     * Returns the target of the KX record
     */
    open var target: Name = Name.empty


    override val `object`: DnsRecord
        get() = KXRecord()

    /**
     * Creates a KX Record from the given data
     *
     * @param preference The preference of this KX.  Records with lower priority
     * are preferred.
     * @param target The host that authority is delegated to
     */
    constructor(name: Name, dclass: Int, ttl: Long, preference: Int, target: Name) : super(
        name, DnsRecordType.KX, dclass, ttl, preference, "preference", target, "target"
    )

    companion object {
        private const val serialVersionUID = 7448568832769757809L
    }
}
