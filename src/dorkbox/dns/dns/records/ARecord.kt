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
import dorkbox.dns.dns.utils.Address
import dorkbox.dns.dns.utils.Tokenizer
import dorkbox.netUtil.IP
import dorkbox.netUtil.IPv4.isFamily
import dorkbox.netUtil.IPv4.length
import dorkbox.netUtil.IPv4.toString
import java.io.IOException
import java.net.InetAddress
import java.net.UnknownHostException

/**
 * Address Record - maps a domain name to an Internet address
 *
 * @author Brian Wellington
 */
class ARecord : DnsRecord {
    private var addr = 0

    internal constructor() {}

    override val `object`: DnsRecord
        get() = ARecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        addr = fromArray(`in`.readByteArray(4))
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeU32(addr.toLong() and 0xFFFFFFFFL)
    }

    /**
     * Converts rdata to a String
     */
    override fun rrToString(sb: StringBuilder) {
        toString(addr, sb)
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        addr = fromArray(st.getAddressBytes(Address.IPv4))
    }

    /**
     * Creates an A Record from the given data
     *
     * @param address The address that the name refers to
     */
    constructor(name: Name?, dclass: Int, ttl: Long, address: InetAddress) : super(name ?: Name(IP.toString(address), null), DnsRecordType.A, dclass, ttl) {
        require(isFamily(address)) { "invalid IPv4 address" }
        addr = fromArray(address.address)
    }

    /**
     * Creates an A Record from the given data
     *
     * @param address The address that the name refers to as a byte array. This value is NOT COPIED.
     */
    constructor(name: Name?, dclass: Int, ttl: Long, address: ByteArray) : super(name!!, DnsRecordType.A, dclass, ttl) {
        require(address.size == length) { "invalid IPv4 address" }
        addr = fromArray(address)
    }

    /**
     * Returns the Internet address
     */
    val address: InetAddress?
        get() = try {
            InetAddress.getByAddress(name.toString(true), toArray(addr))
        } catch (e: UnknownHostException) {
            null
        }

    companion object {
        private const val serialVersionUID = -2172609200849142323L
        private fun toArray(addr: Int): ByteArray {
            val bytes = ByteArray(4)
            bytes[0] = (addr ushr 24 and 0xFF).toByte()
            bytes[1] = (addr ushr 16 and 0xFF).toByte()
            bytes[2] = (addr ushr 8 and 0xFF).toByte()
            bytes[3] = (addr and 0xFF).toByte()
            return bytes
        }

        private fun fromArray(array: ByteArray): Int {
            return array[0].toInt() and 0xFF shl 24 or (array[1].toInt() and 0xFF shl 16) or (array[2].toInt() and 0xFF shl 8) or (array[3].toInt() and 0xFF)
        }
    }
}
