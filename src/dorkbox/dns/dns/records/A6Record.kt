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
import dorkbox.netUtil.IPv6.isFamily
import dorkbox.netUtil.IPv6.toAddress
import java.io.IOException
import java.net.InetAddress

/**
 * A6 Record - maps a domain name to an IPv6 address (experimental)
 *
 * @author Brian Wellington
 */
class A6Record : DnsRecord {
    /**
     * Returns the number of bits in the prefix
     */
    var prefixBits = 0
        private set

    /**
     * Returns the address suffix
     */
    var suffix: InetAddress? = null
        private set

    /**
     * Returns the address prefix
     */
    var prefix: Name? = null
        private set

    internal constructor() {}

    override val `object`: DnsRecord
        get() = A6Record()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        prefixBits = `in`.readU8()
        val suffixbits = 128 - prefixBits
        val suffixbytes = (suffixbits + 7) / 8
        if (prefixBits < 128) {
            val bytes = ByteArray(16)
            `in`.readByteArray(bytes, 16 - suffixbytes, suffixbytes)
            suffix = InetAddress.getByAddress(bytes)
        }
        if (prefixBits > 0) {
            prefix = Name(`in`)
        }
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeU8(prefixBits)
        if (suffix != null) {
            val suffixbits = 128 - prefixBits
            val suffixbytes = (suffixbits + 7) / 8
            val data = suffix!!.address
            out.writeByteArray(data, 16 - suffixbytes, suffixbytes)
        }

        if (prefix != null) {
            prefix!!.toWire(out, null, canonical)
        }
    }

    /**
     * Converts rdata to a String
     */
    override fun rrToString(sb: StringBuilder) {
        sb.append(prefixBits)
        if (suffix != null) {
            sb.append(" ")
            sb.append(suffix!!.hostAddress)
        }
        if (prefix != null) {
            sb.append(" ")
            sb.append(prefix)
        }
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        prefixBits = st.getUInt8()
        if (prefixBits > 128) {
            throw st.exception("prefix bits must be [0..128]")
        } else if (prefixBits < 128) {
            val s = st.getString()
            suffix = try {
                toAddress(s)
            } catch (e: Exception) {
                throw TextParseException("Invalid address: $s", e)
            }
        }
        if (prefixBits > 0) {
            prefix = st.getName(origin)
        }
    }

    /**
     * Creates an A6 Record from the given data
     *
     * @param prefixBits The number of bits in the address prefix
     * @param suffix The address suffix
     * @param prefix The name of the prefix
     */
    constructor(name: Name, dclass: Int, ttl: Long, prefixBits: Int, suffix: InetAddress?, prefix: Name?) : super(
        name, DnsRecordType.A6, dclass, ttl
    ) {
        this.prefixBits = checkU8("prefixBits", prefixBits)
        require(!(suffix != null && !isFamily(suffix))) { "invalid IPv6 address" }
        this.suffix = suffix

        if (prefix != null) {
            this.prefix = checkName("prefix", prefix)
        }
    }

    companion object {
        private const val serialVersionUID = -8815026887337346789L
    }
}
