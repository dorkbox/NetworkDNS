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
 * ISDN - identifies the ISDN number and subaddress associated with a name.
 *
 * @author Brian Wellington
 */
class ISDNRecord : DnsRecord {
    private lateinit var address: ByteArray
    private var subAddress: ByteArray? = null

    internal constructor() {}

    override val `object`: DnsRecord
        get() = ISDNRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        address = `in`.readCountedString()
        if (`in`.remaining() > 0) {
            subAddress = `in`.readCountedString()
        }
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeCountedString(address)
        if (subAddress != null) {
            out.writeCountedString(subAddress!!)
        }
    }

    override fun rrToString(sb: StringBuilder) {
        sb.append(byteArrayToString(address, true))
        if (subAddress != null) {
            sb.append(" ")
            sb.append(byteArrayToString(subAddress!!, true))
        }
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        try {
            address = byteArrayFromString(st.getString())
            val t = st.get()
            if (t.isString) {
                subAddress = byteArrayFromString(t.value!!)
            } else {
                st.unget()
            }
        } catch (e: TextParseException) {
            throw st.exception(e.message ?: "")
        }
    }

    /**
     * Creates an ISDN Record from the given data
     *
     * @param address The ISDN number associated with the domain.
     * @param subAddress The subaddress, if any.
     *
     * @throws IllegalArgumentException One of the strings is invalid.
     */
    constructor(name: Name?, dclass: Int, ttl: Long, address: String?, subAddress: String?) : super(
        name!!, DnsRecordType.ISDN, dclass, ttl
    ) {
        try {
            this.address = byteArrayFromString(address!!)
            if (subAddress != null) {
                this.subAddress = byteArrayFromString(subAddress)
            }
        } catch (e: TextParseException) {
            throw IllegalArgumentException(e.message)
        }
    }

    /**
     * Returns the ISDN number associated with the domain.
     */
    fun getAddress(): String {
        return byteArrayToString(address, false)
    }

    /**
     * Returns the ISDN subaddress, or null if there is none.
     */
    fun getSubAddress(): String? {
        return if (subAddress == null) {
            null
        } else byteArrayToString(subAddress!!, false)
    }

    companion object {
        private const val serialVersionUID = -8730801385178968798L
    }
}
