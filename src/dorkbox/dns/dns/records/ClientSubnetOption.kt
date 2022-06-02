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

import dorkbox.dns.dns.DnsInput
import dorkbox.dns.dns.DnsOutput
import dorkbox.dns.dns.exceptions.WireParseException
import dorkbox.dns.dns.utils.Address
import dorkbox.dns.dns.utils.Address.familyOf
import dorkbox.netUtil.IP.truncate
import dorkbox.netUtil.IPv4
import dorkbox.netUtil.IPv6
import java.net.InetAddress
import java.net.UnknownHostException

/**
 * The Client Subnet EDNS Option, defined in
 * http://tools.ietf.org/html/draft-vandergaast-edns-client-subnet-00
 * ("Client subnet in DNS requests").
 *
 *
 * The option is used to convey information about the IP address of the
 * originating client, so that an authoritative server can make decisions
 * based on this address, rather than the address of the intermediate
 * caching name server.
 *
 *
 * The option is transmitted as part of an OPTRecord in the additional section
 * of a DNS message, as defined by RFC 2671 (EDNS0).
 *
 *
 * The wire format of the option contains a 2-byte length field (1 for IPv4, 2
 * for IPv6), a 1-byte source netmask, a 1-byte scope netmask, and an address
 * truncated to the source netmask length (where the final octet is padded with
 * bits set to 0)
 *
 * @author Brian Wellington
 * @author Ming Zhou &lt;mizhou@bnivideo.com&gt;, Beaumaris Networks
 * @see OPTRecord
 */
class ClientSubnetOption : EDNSOption {
    /**
     * Returns the family of the network address.  This will be either IPv4 (1)
     * or IPv6 (2).
     */
    var family = 0
        private set

    /**
     * Returns the source netmask.
     */
    var sourceNetmask = 0
        private set

    /**
     * Returns the scope netmask.
     */
    var scopeNetmask = 0
        private set

    /**
     * Returns the IP address of the client.
     */
    var address: InetAddress? = null
        private set

    internal constructor() : super(Code.CLIENT_SUBNET) {}

    /**
     * Construct a Client Subnet option with scope netmask set to 0.
     *
     * @param sourceNetmask The length of the netmask pertaining to the query.
     * In replies, it mirrors the same value as in the requests.
     * @param address The address of the client.
     *
     * @see ClientSubnetOption
     */
    constructor(sourceNetmask: Int, address: InetAddress) : this(sourceNetmask, 0, address) {}

    /**
     * Construct a Client Subnet option.  Note that the number of significant bits
     * in the address must not be greater than the supplied source netmask.  There
     * may also be issues related to Java's handling of mapped addresses
     *
     * @param sourceNetmask The length of the netmask pertaining to the query.
     * In replies, it mirrors the same value as in the requests.
     * @param scopeNetmask The length of the netmask pertaining to the reply.
     * In requests, it MUST be set to 0.  In responses, this may or may not match
     * the source netmask.
     * @param address The address of the client.
     */
    constructor(sourceNetmask: Int, scopeNetmask: Int, address: InetAddress) : super(Code.CLIENT_SUBNET) {
        family = familyOf(address)
        this.sourceNetmask = checkMaskLength("source netmask", family, sourceNetmask)
        this.scopeNetmask = checkMaskLength("scope netmask", family, scopeNetmask)
        this.address = truncate(address, sourceNetmask)
        require(address == this.address) { "source netmask is not " + "valid for address" }
    }

    @Throws(WireParseException::class)
    override fun optionFromWire(`in`: DnsInput) {
        family = `in`.readU16()
        if (family != Address.IPv4 && family != Address.IPv6) {
            throw WireParseException("unknown address family")
        }
        sourceNetmask = `in`.readU8()
        if (sourceNetmask > getLength(family) * 8) {
            throw WireParseException("invalid source netmask")
        }
        scopeNetmask = `in`.readU8()
        if (scopeNetmask > getLength(family) * 8) {
            throw WireParseException("invalid scope netmask")
        }

        // Read the truncated address
        val addr = `in`.readByteArray()
        if (addr.size != (sourceNetmask + 7) / 8) {
            throw WireParseException("invalid address")
        }

        // Convert it to a full length address.
        val fulladdr = ByteArray(getLength(family))
        System.arraycopy(addr, 0, fulladdr, 0, addr.size)
        address = try {
            InetAddress.getByAddress(fulladdr)
        } catch (e: UnknownHostException) {
            throw WireParseException("invalid address", e)
        }
        val tmp = truncate(address!!, sourceNetmask)
        if (tmp != address) {
            throw WireParseException("invalid padding")
        }
    }

    override fun optionToWire(out: DnsOutput) {
        out.writeU16(family)
        out.writeU8(sourceNetmask)
        out.writeU8(scopeNetmask)
        out.writeByteArray(address!!.address, 0, (sourceNetmask + 7) / 8)
    }

    override fun optionToString(): String {
        val sb = StringBuilder()
        sb.append(address!!.hostAddress)
        sb.append("/")
        sb.append(sourceNetmask)
        sb.append(", scope netmask ")
        sb.append(scopeNetmask)
        return sb.toString()
    }

    companion object {
        private const val serialVersionUID = -3868158449890266347L
        private fun getLength(family: Int): Int {
            val max: Int
            max = if (family == Address.IPv4) {
                IPv4.length
            } else if (family == Address.IPv6) {
                IPv6.length
            } else {
                throw IllegalArgumentException("Invalid family address!")
            }
            return max
        }

        private fun checkMaskLength(field: String, family: Int, `val`: Int): Int {
            val max = getLength(family) * 8
            require(!(`val` < 0 || `val` > max)) { "\"$field\" $`val` must be in the range [0..$max]" }
            return `val`
        }
    }
}
