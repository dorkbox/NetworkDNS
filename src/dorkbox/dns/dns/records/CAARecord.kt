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
 * Certification Authority Authorization
 *
 * @author Brian Wellington
 */
class CAARecord : DnsRecord {
    internal constructor() {}

    /**
     * Returns the flags.
     */
    var flags = 0
        private set

    private lateinit var tag: ByteArray
    private lateinit var value: ByteArray

    object Flags {
        const val IssuerCritical = 128
    }

    override val `object`: DnsRecord
        get() = CAARecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        flags = `in`.readU8()
        tag = `in`.readCountedString()
        value = `in`.readByteArray()
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeU8(flags)
        out.writeCountedString(tag)
        out.writeByteArray(value)
    }

    override fun rrToString(sb: StringBuilder) {
        sb.append(flags)
        sb.append(" ")
        sb.append(byteArrayToString(tag, false))
        sb.append(" ")
        sb.append(byteArrayToString(value, true))
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        flags = st.getUInt8()
        try {
            tag = byteArrayFromString(st.getString())
            value = byteArrayFromString(st.getString())
        } catch (e: TextParseException) {
            throw st.exception(e.message ?: "")
        }
    }

    /**
     * Creates an CAA Record from the given data.
     *
     * @param flags The flags.
     * @param tag The tag.
     * @param value The value.
     */
    constructor(name: Name, dclass: Int, ttl: Long, flags: Int, tag: String, value: String) : super(
        name, DnsRecordType.CAA, dclass, ttl
    ) {
        this.flags = checkU8("flags", flags)
        try {
            this.tag = byteArrayFromString(tag)
            this.value = byteArrayFromString(value)
        } catch (e: TextParseException) {
            throw IllegalArgumentException(e.message)
        }
    }

    /**
     * Returns the tag.
     */
    fun getTag(): String {
        return byteArrayToString(tag, false)
    }

    /**
     * Returns the value
     */
    fun getValue(): String {
        return byteArrayToString(value, false)
    }

    companion object {
        private const val serialVersionUID = 8544304287274216443L
    }
}
