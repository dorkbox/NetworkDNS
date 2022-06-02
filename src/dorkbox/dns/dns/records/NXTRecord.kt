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
import dorkbox.dns.dns.constants.DnsRecordType.string
import dorkbox.dns.dns.constants.DnsRecordType.value
import dorkbox.dns.dns.utils.Tokenizer
import java.io.IOException
import java.util.*

/**
 * Next name - this record contains the following name in an ordered list
 * of names in the zone, and a set of types for which records exist for
 * this name.  The presence of this record in a response signifies a
 * failed query for data in a DNSSEC-signed zone.
 *
 * @author Brian Wellington
 */
class NXTRecord : DnsRecord {
    /**
     * Returns the next name
     */
    var next: Name? = null
        private set

    /**
     * Returns the set of types defined for this name
     */
    var bitmap: BitSet? = null
        private set

    internal constructor() {}

    override val `object`: DnsRecord
        get() = NXTRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        next = Name(`in`)
        bitmap = BitSet()
        val bitmapLength = `in`.remaining()
        for (i in 0 until bitmapLength) {
            val t = `in`.readU8()
            for (j in 0..7) {
                if (t and (1 shl 7) - j != 0) {
                    bitmap!!.set(i * 8 + j)
                }
            }
        }
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        next!!.toWire(out, null, canonical)
        val length = bitmap!!.length()
        var i = 0
        var t = 0
        while (i < length) {
            t = t or if (bitmap!![i]) 1 shl 7 - i % 8 else 0
            if (i % 8 == 7 || i == length - 1) {
                out.writeU8(t)
                t = 0
            }
            i++
        }
    }

    /**
     * Converts rdata to a String
     */
    override fun rrToString(sb: StringBuilder) {
        sb.append(next)
        val length = bitmap!!.length()
        for (i in 0 until length) {
            if (bitmap!![i]) {
                sb.append(" ")
                sb.append(string(i))
            }
        }
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        next = st.getName(origin)
        bitmap = BitSet()
        while (true) {
            val t = st.get()
            if (!t.isString) {
                break
            }
            val typecode = value(t.value!!, true)
            if (typecode <= 0 || typecode > 128) {
                throw st.exception("Invalid type: " + t.value)
            }
            bitmap!!.set(typecode)
        }
        st.unget()
    }

    /**
     * Creates an NXT Record from the given data
     *
     * @param next The following name in an ordered list of the zone
     * @param bitmap The set of type for which records exist at this name
     */
    constructor(name: Name?, dclass: Int, ttl: Long, next: Name?, bitmap: BitSet?) : super(
        name!!, DnsRecordType.NXT, dclass, ttl
    ) {
        this.next = checkName("next", next!!)
        this.bitmap = bitmap
    }

    companion object {
        private const val serialVersionUID = -8851454400765507520L
    }
}
