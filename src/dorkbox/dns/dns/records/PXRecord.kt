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
import dorkbox.dns.dns.utils.Tokenizer
import java.io.IOException

/**
 * X.400 mail mapping record.
 *
 * @author Brian Wellington
 */
class PXRecord : DnsRecord {
    /**
     * Gets the preference of the route.
     */
    var preference = 0
        private set

    /**
     * Gets the RFC 822 component of the mail address.
     */
    var map822: Name? = null
        private set

    /**
     * Gets the X.400 component of the mail address.
     */
    var mapX400: Name? = null
        private set

    internal constructor() {}

    override val `object`: DnsRecord
        get() = PXRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        preference = `in`.readU16()
        map822 = Name(`in`)
        mapX400 = Name(`in`)
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeU16(preference)
        map822!!.toWire(out, null, canonical)
        mapX400!!.toWire(out, null, canonical)
    }

    /**
     * Converts the PX Record to a String
     */
    override fun rrToString(sb: StringBuilder) {
        sb.append(preference)
        sb.append(" ")
        sb.append(map822)
        sb.append(" ")
        sb.append(mapX400)
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        preference = st.getUInt16()
        map822 = st.getName(origin)
        mapX400 = st.getName(origin)
    }

    /**
     * Creates an PX Record from the given data
     *
     * @param preference The preference of this mail address.
     * @param map822 The RFC 822 component of the mail address.
     * @param mapX400 The X.400 component of the mail address.
     */
    constructor(name: Name?, dclass: Int, ttl: Long, preference: Int, map822: Name?, mapX400: Name?) : super(
        name!!, DnsRecordType.PX, dclass, ttl
    ) {
        this.preference = checkU16("preference", preference)
        this.map822 = checkName("map822", map822!!)
        this.mapX400 = checkName("mapX400", mapX400!!)
    }

    companion object {
        private const val serialVersionUID = 1811540008806660667L
    }
}
