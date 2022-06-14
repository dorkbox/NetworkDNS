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
 * X25 - identifies the PSDN (Public Switched Data Network) address in the
 * X.121 numbering plan associated with a name.
 *
 * @author Brian Wellington
 */
class X25Record : DnsRecord {
    private lateinit var address: ByteArray

    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = X25Record()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        address = `in`.readCountedString()
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeCountedString(address)
    }

    override fun rrToString(sb: StringBuilder) {
        sb.append(byteArrayToString(address, true))
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        val addr = st.getString()
        val address = checkAndConvertAddress(addr) ?: throw st.exception("invalid PSDN address $addr")
        this.address = address
    }

    /**
     * Creates an X25 Record from the given data
     *
     * @param address The X.25 PSDN address.
     *
     * @throws IllegalArgumentException The address is not a valid PSDN address.
     */
    constructor(name: Name, dclass: Int, ttl: Long, address: String) : super(name, DnsRecordType.X25, dclass, ttl) {
        val address = checkAndConvertAddress(address)
        requireNotNull(address) { "invalid PSDN address $address" }
        this.address = address
    }

    /**
     * Returns the X.25 PSDN address.
     */
    fun getAddress(): String {
        return byteArrayToString(address, false)
    }

    companion object {
        private const val serialVersionUID = 4267576252335579764L
        private fun checkAndConvertAddress(address: String): ByteArray? {
            val length = address.length
            val out = ByteArray(length)
            for (i in 0 until length) {
                val c = address[i]
                if (!Character.isDigit(c)) {
                    return null
                }
                out[i] = c.code.toByte()
            }
            return out
        }
    }
}
