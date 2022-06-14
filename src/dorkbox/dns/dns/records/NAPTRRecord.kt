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
import dorkbox.dns.dns.exceptions.TextParseException
import dorkbox.dns.dns.utils.Tokenizer
import java.io.IOException

/**
 * Name Authority Pointer Record  - specifies rewrite rule, that when applied
 * to an existing string will produce a new domain.
 *
 * @author Chuck Santos
 */
class NAPTRRecord : DnsRecord {
    /**
     * Returns the order
     */
    var order = 0
        private set

    /**
     * Returns the preference
     */
    var preference = 0
        private set

    private lateinit var flags: ByteArray
    private lateinit var service: ByteArray
    private lateinit var regexp: ByteArray

    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = NAPTRRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        order = `in`.readU16()
        preference = `in`.readU16()
        flags = `in`.readCountedString()
        service = `in`.readCountedString()
        regexp = `in`.readCountedString()
        additionalName = Name(`in`)
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeU16(order)
        out.writeU16(preference)
        out.writeCountedString(flags)
        out.writeCountedString(service)
        out.writeCountedString(regexp)
        additionalName!!.toWire(out, null, canonical)
    }

    /**
     * Converts rdata to a String
     */
    override fun rrToString(sb: StringBuilder) {
        sb.append(order)
        sb.append(" ")
        sb.append(preference)
        sb.append(" ")
        sb.append(byteArrayToString(flags, true))
        sb.append(" ")
        sb.append(byteArrayToString(service, true))
        sb.append(" ")
        sb.append(byteArrayToString(regexp, true))
        sb.append(" ")
        sb.append(additionalName)
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        order = st.getUInt16()
        preference = st.getUInt16()
        try {
            flags = byteArrayFromString(st.getString())
            service = byteArrayFromString(st.getString())
            regexp = byteArrayFromString(st.getString())
        } catch (e: TextParseException) {
            throw st.exception(e.message ?: "")
        }
        additionalName = st.getName(origin)
    }

    /**
     * Creates an NAPTR Record from the given data
     *
     * @param order The order of this NAPTR.  Records with lower order are
     * preferred.
     * @param preference The preference, used to select between records at the
     * same order.
     * @param flags The control aspects of the NAPTRRecord.
     * @param service The service or protocol available down the rewrite path.
     * @param regexp The regular/substitution expression.
     * @param replacement The domain-name to query for the next DNS resource
     * record, depending on the value of the flags field.
     *
     * @throws IllegalArgumentException One of the strings has invalid escapes
     */
    constructor(
        name: Name?,
        dclass: Int,
        ttl: Long,
        order: Int,
        preference: Int,
        flags: String?,
        service: String?,
        regexp: String?,
        replacement: Name?
    ) : super(
        name!!, DnsRecordType.NAPTR, dclass, ttl
    ) {
        this.order = checkU16("order", order)
        this.preference = checkU16("preference", preference)
        try {
            this.flags = byteArrayFromString(flags!!)
            this.service = byteArrayFromString(service!!)
            this.regexp = byteArrayFromString(regexp!!)
        } catch (e: TextParseException) {
            throw IllegalArgumentException(e.message)
        }
        additionalName = checkName("replacement", replacement!!)
    }

    /**
     * Returns flags
     */
    fun getFlags(): String {
        return byteArrayToString(flags, false)
    }

    /**
     * Returns service
     */
    fun getService(): String {
        return byteArrayToString(service, false)
    }

    /**
     * Returns regexp
     */
    fun getRegexp(): String {
        return byteArrayToString(regexp, false)
    }

    companion object {
        private const val serialVersionUID = 5191232392044947002L
    }
}
