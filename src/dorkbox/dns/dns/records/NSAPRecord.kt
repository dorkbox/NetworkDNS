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
import dorkbox.dns.dns.utils.base16.toString
import java.io.ByteArrayOutputStream
import java.io.IOException

/**
 * NSAP Address Record.
 *
 * @author Brian Wellington
 */
class NSAPRecord : DnsRecord {
    private lateinit var address: ByteArray

    internal constructor()

    override val dnsRecord: DnsRecord
        get() = NSAPRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        address = `in`.readByteArray()
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeByteArray(address)
    }

    override fun rrToString(sb: StringBuilder) {
        sb.append("0x").append(toString(address))
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        address = checkAndConvertAddress(st.getString())
    }

    /**
     * Creates an NSAP Record from the given data
     *
     * @param address The NSAP address.
     *
     * @throws IllegalArgumentException The address is not a valid NSAP address.
     */
    constructor(name: Name?, dclass: Int, ttl: Long, address: String) : super(name!!, DnsRecordType.NSAP, dclass, ttl) {
        this.address = checkAndConvertAddress(address)
    }

    /**
     * Returns the NSAP address.
     */
    fun getAddress(): String {
        return byteArrayToString(address, false)
    }

    companion object {
        private const val serialVersionUID = -1037209403185658593L
        private fun checkAndConvertAddress(address: String): ByteArray {
            if (!address.substring(0, 2).equals("0x", ignoreCase = true)) {
                throw IllegalArgumentException("invalid NSAP address $address")
            }
            val bytes = ByteArrayOutputStream()
            var partial = false
            var current = 0
            for (i in 2 until address.length) {
                val c = address[i]
                if (c == '.') {
                    continue
                }
                val value = c.digitToIntOrNull(16) ?: -1
                if (value == -1) {
                    throw IllegalArgumentException("invalid NSAP address $address")
                }
                if (partial) {
                    current += value
                    bytes.write(current)
                    partial = false
                } else {
                    current = value shl 4
                    partial = true
                }
            }

            return if (partial) {
                throw IllegalArgumentException("invalid NSAP address $address")
            } else bytes.toByteArray()
        }
    }
}
