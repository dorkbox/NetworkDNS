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
import dorkbox.dns.dns.exceptions.WireParseException
import dorkbox.dns.dns.utils.Address
import dorkbox.dns.dns.utils.Tokenizer
import java.io.IOException
import java.net.Inet6Address
import java.net.InetAddress
import java.util.*

/**
 * IPsec Keying Material (RFC 4025)
 *
 * @author Brian Wellington
 */
class IPSECKEYRecord : DnsRecord {
    /**
     * Returns the record's precedence.
     */
    var precedence = 0
        private set

    /**
     * Returns the record's gateway type.
     */
    var gatewayType = 0
        private set

    /**
     * Returns the record's algorithm type.
     */
    var algorithmType = 0
        private set

    /**
     * Returns the record's gateway.
     */
    var gateway: Any? = null
        private set

    /**
     * Returns the record's public key
     */
    var key: ByteArray = byteArrayOf()
        private set

    object Algorithm {
        const val DSA = 1
        const val RSA = 2
    }

    object Gateway {
        const val None = 0
        const val IPv4 = 1
        const val IPv6 = 2
        const val Name = 3
    }

    internal constructor() {}

    override val `object`: DnsRecord
        get() = IPSECKEYRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        precedence = `in`.readU8()
        gatewayType = `in`.readU8()
        algorithmType = `in`.readU8()
        gateway = when (gatewayType) {
            Gateway.None -> null
            Gateway.IPv4 -> InetAddress.getByAddress(`in`.readByteArray(4))
            Gateway.IPv6 -> InetAddress.getByAddress(`in`.readByteArray(16))
            Gateway.Name -> Name(`in`)
            else -> throw WireParseException("invalid gateway type")
        }
        if (`in`.remaining() > 0) {
            key = `in`.readByteArray()
        }
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeU8(precedence)
        out.writeU8(gatewayType)
        out.writeU8(algorithmType)
        when (gatewayType) {
            Gateway.None -> {}
            Gateway.IPv4, Gateway.IPv6 -> {
                val gatewayAddr = gateway as InetAddress?
                out.writeByteArray(gatewayAddr!!.address)
            }
            Gateway.Name -> {
                val gatewayName = gateway as Name?
                gatewayName!!.toWire(out, null, canonical)
            }
        }
        if (key != null) {
            out.writeByteArray(key!!)
        }
    }

    override fun rrToString(sb: StringBuilder) {
        sb.append(precedence)
        sb.append(" ")
        sb.append(gatewayType)
        sb.append(" ")
        sb.append(algorithmType)
        sb.append(" ")
        when (gatewayType) {
            Gateway.None -> sb.append(".")
            Gateway.IPv4, Gateway.IPv6 -> {
                val gatewayAddr = gateway as InetAddress?
                sb.append(gatewayAddr!!.hostAddress)
            }
            Gateway.Name -> sb.append(gateway)
        }
        if (key != null) {
            sb.append(" ")
            sb.append(Base64.getEncoder().encodeToString(key))
        }
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        precedence = st.getUInt8()
        gatewayType = st.getUInt8()
        algorithmType = st.getUInt8()
        gateway = when (gatewayType) {
            Gateway.None -> {
                val s = st.getString()
                if (s != ".") {
                    throw TextParseException("invalid gateway format")
                }
                null
            }
            Gateway.IPv4 -> st.getAddress(Address.IPv4)
            Gateway.IPv6 -> st.getAddress(Address.IPv6)
            Gateway.Name -> st.getName(origin)
            else -> throw WireParseException("invalid gateway type")
        }
        key = st.getBase64(true)!!
    }

    /**
     * Creates an IPSECKEY Record from the given data.
     *
     * @param precedence The record's precedence.
     * @param gatewayType The record's gateway type.
     * @param algorithmType The record's algorithm type.
     * @param gateway The record's gateway.
     * @param key The record's public key.
     */
    constructor(
        name: Name,
        dclass: Int,
        ttl: Long,
        precedence: Int,
        gatewayType: Int,
        algorithmType: Int,
        gateway: Any,
        key: ByteArray
    ) : super(
        name, DnsRecordType.IPSECKEY, dclass, ttl
    ) {
        this.precedence = checkU8("precedence", precedence)
        this.gatewayType = checkU8("gatewayType", gatewayType)
        this.algorithmType = checkU8("algorithmType", algorithmType)
        when (gatewayType) {
            Gateway.None -> this.gateway = null
            Gateway.IPv4 -> {
                require(gateway is InetAddress) { "\"gateway\" " + "must be an IPv4 " + "address" }
                this.gateway = gateway
            }
            Gateway.IPv6 -> {
                require(gateway is Inet6Address) { "\"gateway\" " + "must be an IPv6 " + "address" }
                this.gateway = gateway
            }
            Gateway.Name -> {
                require(gateway is Name) { "\"gateway\" " + "must be a DNS " + "name" }
                this.gateway = checkName("gateway", (gateway as Name?)!!)
            }
            else -> throw IllegalArgumentException("\"gatewayType\" " + "must be between 0 and 3")
        }
        this.key = key
    }

    companion object {
        private const val serialVersionUID = 3050449702765909687L
    }
}
