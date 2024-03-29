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
 * Pointer Record  - maps a domain name representing an Internet Address to
 * a hostname.
 *
 * @author Brian Wellington
 */
class PTRRecord : SingleCompressedNameBase {
    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = PTRRecord()

    /**
     * Creates a new PTR Record with the given data
     *
     * @param target The name of the machine with this address
     */
    constructor(name: Name, dclass: Int, ttl: Long, target: Name) : super(name, DnsRecordType.PTR, dclass, ttl, target, "target") {}

    /**
     * Gets the target of the PTR Record
     */
    var target: Name
        get() = singleName
        set(target) {
            singleName = target
        }

    companion object {
        private const val serialVersionUID = -8321636610425434192L
    }
}
