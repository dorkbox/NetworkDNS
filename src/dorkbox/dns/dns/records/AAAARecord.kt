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
import dorkbox.netUtil.IPv6.isFamily
import dorkbox.netUtil.IPv6.length
import java.io.IOException
import java.net.InetAddress
import java.net.UnknownHostException

/**
 * IPv6 Address Record - maps a domain name to an IPv6 address
 *
 * @author Brian Wellington
 */
class AAAARecord : DnsRecord {
    private lateinit var addr: ByteArray

    internal constructor() {}

    override val `object`: DnsRecord
        get() = AAAARecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        addr = `in`.readByteArray(16)
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeByteArray(addr)
    }

    /**
     * Converts rdata to a String
     */
    override fun rrToString(sb: StringBuilder) {
        val addr: InetAddress = try {
            InetAddress.getByAddress(null, addr)
        } catch (ignored: UnknownHostException) {
            return
        }

        if (addr.address.size == 4) {
            // Deal with Java's broken handling of mapped IPv4 addresses.
            sb.append("0:0:0:0:0:ffff:")
            val high = (this.addr[12].toInt() and 0xFF shl 8) + (this.addr[13].toInt() and 0xFF)
            val low = (this.addr[14].toInt() and 0xFF shl 8) + (this.addr[15].toInt() and 0xFF)
            sb.append(Integer.toHexString(high))
            sb.append(':')
            sb.append(Integer.toHexString(low))
            return
        }
        sb.append(addr.hostAddress)
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        addr = st.getAddressBytes(Address.IPv6)
    }

    /**
     * Creates an AAAA Record from the given data
     *
     * @param address The address that the name refers
     */
    constructor(name: Name?, dclass: Int, ttl: Long, address: InetAddress) : super(name ?: Name(IP.toString(address), null), DnsRecordType.AAAA, dclass, ttl) {
        require(isFamily(address)) { "invalid IPv6 address" }
        this.addr = address.address
    }

    /**
     * Creates an AAAA Record from the given data
     *
     * @param address The address that the name refers to as a byte array. This value is NOT COPIED.
     */
    constructor(name: Name?, dclass: Int, ttl: Long, address: ByteArray) : super(name ?: Name(IP.toString(address), null), DnsRecordType.AAAA, dclass, ttl) {
        require(address.size == length) { "invalid IPv6 address" }
        this.addr = address
    }

    /**
     * Returns the address
     */
    val address: InetAddress?
        get() {
            return try {
                try {
                    InetAddress.getByAddress(name.toString(true), addr)
                } catch (e: Exception) {
                    // name wasn't initialized yet!
                    InetAddress.getByAddress(addr)
                }
            } catch (e: UnknownHostException) {
                null
            }
        }

    companion object {
        private const val serialVersionUID = -4588601512069748050L
    }
}
