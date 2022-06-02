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
import dorkbox.dns.dns.DnsInput
import dorkbox.dns.dns.DnsOutput
import dorkbox.dns.dns.Name
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.constants.DnsRecordType.check
import dorkbox.dns.dns.utils.Tokenizer
import java.io.IOException

/**
 * Next SECure name - this record contains the following name in an
 * ordered list of names in the zone, and a set of types for which
 * records exist for this name.  The presence of this record in a response
 * signifies a negative response from a DNSSEC-signed zone.
 *
 *
 * This replaces the NXT record.
 *
 * @author Brian Wellington
 * @author David Blacka
 */
class NSECRecord : DnsRecord {
    /**
     * Returns the next name
     */
    var next: Name? = null
        private set

    private var types: TypeBitmap? = null

    internal constructor() {}

    override val `object`: DnsRecord
        get() = NSECRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        next = Name(`in`)
        types = TypeBitmap(`in`)
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        // Note: The next name is not lowercased.
        next!!.toWire(out, null, false)
        types!!.toWire(out)
    }

    /**
     * Converts rdata to a String
     */
    override fun rrToString(sb: StringBuilder) {
        sb.append(next)
        if (!types!!.empty()) {
            sb.append(' ')
            sb.append(types.toString())
        }
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        next = st.getName(origin)
        types = TypeBitmap(st)
    }

    /**
     * Creates an NSEC Record from the given data.
     *
     * @param next The following name in an ordered list of the zone
     * @param types An array containing the types present.
     */
    constructor(name: Name?, dclass: Int, ttl: Long, next: Name?, types: IntArray) : super(
        name!!, DnsRecordType.NSEC, dclass, ttl
    ) {
        this.next = checkName("next", next!!)
        for (i in types.indices) {
            check(types[i])
        }
        this.types = TypeBitmap(types)
    }

    /**
     * Returns the set of types defined for this name
     */
    fun getTypes(): IntArray {
        return types!!.toArray()
    }

    /**
     * Returns whether a specific type is in the set of types.
     */
    fun hasType(type: Int): Boolean {
        return types!!.contains(type)
    }

    companion object {
        private const val serialVersionUID = -5165065768816265385L
    }
}
