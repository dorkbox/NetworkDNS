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
import dorkbox.dns.dns.records.DNSSEC.toPublicKey
import dorkbox.dns.dns.utils.Options.check
import dorkbox.os.OS.LINE_SEPARATOR
import java.io.IOException
import java.security.PublicKey
import java.util.*

/**
 * The base class for KEY/DNSKEY records, which have identical formats
 *
 * @author Brian Wellington
 */
abstract class KEYBase : DnsRecord {
    /**
     * Returns the flags describing the key's properties
     */
    var flags = 0
        protected set

    /**
     * Returns the protocol that the key was created for
     */
    var protocol = 0
        protected set

    /**
     * Returns the key's algorithm
     */
    var algorithm = 0
        protected set

    /**
     * Returns the binary data representing the key
     */
    var key: ByteArray? = null
        protected set

    /**
     * Returns the key's footprint (after computing it)
     */
    var footprint: Int = -1
        get() {
            if (field < 0) {
                var foot = 0

                val out = DnsOutput()
                rrToWire(out, null, false)

                val rdata = out.toByteArray()
                if (algorithm == DNSSEC.Algorithm.RSAMD5) {
                    val d1 = rdata[rdata.size - 3].toInt() and 0xFF
                    val d2 = rdata[rdata.size - 2].toInt() and 0xFF
                    foot = (d1 shl 8) + d2
                } else {
                    var i: Int
                    i = 0
                    while (i < rdata.size - 1) {
                        val d1 = rdata[i].toInt() and 0xFF
                        val d2 = rdata[i + 1].toInt() and 0xFF
                        foot += (d1 shl 8) + d2
                        i += 2
                    }
                    if (i < rdata.size) {
                        val d1 = rdata[i].toInt() and 0xFF
                        foot += d1 shl 8
                    }
                    foot += foot shr 16 and 0xFFFF
                }

                field = foot and 0xFFFF
            }
            return field
        }
        private set

    /**
     * a PublicKey corresponding to the data in this key.
     *
     * @throws DNSSEC.DNSSECException The key could not be converted.
     */
    val publicKey: PublicKey by lazy {
        val toPublicKey = toPublicKey(this@KEYBase)
        toPublicKey
    }

    protected constructor() {}
    constructor(name: Name, type: Int, dclass: Int, ttl: Long, flags: Int, proto: Int, alg: Int, key: ByteArray?) : super(
        name, type, dclass, ttl
    ) {
        this.flags = checkU16("flags", flags)
        protocol = checkU8("proto", proto)
        algorithm = checkU8("alg", alg)
        this.key = key
    }

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        flags = `in`.readU16()
        protocol = `in`.readU8()
        algorithm = `in`.readU8()

        if (`in`.remaining() > 0) {
            key = `in`.readByteArray()
        }
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeU16(flags)
        out.writeU8(protocol)
        out.writeU8(algorithm)

        if (key != null) {
            out.writeByteArray(key!!)
        }
    }

    /**
     * Converts the DNSKEY/KEY Record to a String
     */
    override fun rrToString(sb: StringBuilder) {
        sb.append(flags)
        sb.append(" ")
        sb.append(protocol)
        sb.append(" ")
        sb.append(algorithm)
        if (key != null) {
            if (check("multiline")) {
                sb.append(" (")
                sb.append(LINE_SEPARATOR)
                sb.append(Base64.getMimeEncoder().encodeToString(key))
                sb.append(LINE_SEPARATOR)
                sb.append(") ; key_tag = ")
                sb.append(footprint)
            } else {
                sb.append(" ")
                sb.append(Base64.getEncoder().encodeToString(key))
            }
        }
    }

    companion object {
        private const val serialVersionUID = 3469321722693285454L
    }
}
