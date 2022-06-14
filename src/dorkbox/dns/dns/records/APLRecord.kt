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
import dorkbox.dns.dns.exceptions.WireParseException
import dorkbox.dns.dns.utils.Address
import dorkbox.dns.dns.utils.Address.familyOf
import dorkbox.dns.dns.utils.Tokenizer
import dorkbox.dns.dns.utils.base16.toString
import dorkbox.netUtil.IPv4
import dorkbox.netUtil.IPv6
import java.io.IOException
import java.net.InetAddress

/**
 * APL - Address Prefix List.  See RFC 3123.
 *
 * @author Brian Wellington
 */
/*
 * Note: this currently uses the same constants as the Address class;
 * this could change if more constants are defined for APL records.
 */
class APLRecord : DnsRecord {
    private lateinit var elements: MutableList<Element>

    class Element(val family: Int, val negative: Boolean, val address: Any, val prefixLength: Int) {

        /**
         * Creates an APL element corresponding to an IPv4 or IPv6 prefix.
         *
         * @param negative Indicates if this prefix is a negation.
         * @param address The IPv4 or IPv6 address.
         * @param prefixLength The length of this prefix, in bits.
         *
         * @throws IllegalArgumentException The prefix length is invalid.
         */
        constructor(negative: Boolean, address: InetAddress, prefixLength: Int) : this(
            familyOf(address),
            negative,
            address,
            prefixLength
        )

        init {
            require(validatePrefixLength(family, prefixLength)) { "invalid prefix " + "length" }
        }

        override fun hashCode(): Int {
            return address.hashCode() + prefixLength + if (negative) 1 else 0
        }

        override fun equals(arg: Any?): Boolean {
            if (arg == null || arg !is Element) {
                return false
            }
            val elt = arg
            return family == elt.family && negative == elt.negative && prefixLength == elt.prefixLength && address == elt.address
        }

        override fun toString(): String {
            val sb = StringBuilder()
            if (negative) {
                sb.append("!")
            }
            sb.append(family)
            sb.append(":")
            if (family == Address.IPv4 || family == Address.IPv6) {
                sb.append((address as InetAddress).hostAddress)
            } else {
                sb.append(toString((address as ByteArray)))
            }
            sb.append("/")
            sb.append(prefixLength)
            return sb.toString()
        }
    }

    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = APLRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        elements = ArrayList(1)

        while (`in`.remaining() != 0) {
            val family = `in`.readU16()
            val prefix = `in`.readU8()
            var length = `in`.readU8()
            val negative = length and 0x80 != 0
            length = length and 0x80.inv()
            var data = `in`.readByteArray(length)
            var element: Element
            if (!validatePrefixLength(family, prefix)) {
                throw WireParseException("invalid prefix length")
            }
            if (family == Address.IPv4 || family == Address.IPv6) {
                data = if (family == Address.IPv4) {
                    parseAddress(data, IPv4.length)
                } else {
                    parseAddress(data, IPv6.length)
                }
                val addr = InetAddress.getByAddress(data)
                element = Element(negative, addr, prefix)
            } else {
                element = Element(family, negative, data, prefix)
            }
            elements.add(element)
        }
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        for (element in elements) {
            var length = 0
            var data: ByteArray
            if (element.family == Address.IPv4 || element.family == Address.IPv6) {
                val addr = element.address as InetAddress
                data = addr.address
                length = addressLength(data)
            } else {
                data = element.address as ByteArray
                length = data.size
            }
            var wlength = length
            if (element.negative) {
                wlength = wlength or 0x80
            }
            out.writeU16(element.family)
            out.writeU8(element.prefixLength)
            out.writeU8(wlength)
            out.writeByteArray(data, 0, length)
        }
    }

    override fun rrToString(sb: StringBuilder) {
        val it: Iterator<*> = elements.iterator()
        while (it.hasNext()) {
            val element = it.next() as Element
            sb.append(element)
            if (it.hasNext()) {
                sb.append(" ")
            }
        }
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        elements = ArrayList(1)
        while (true) {
            val t = st.get()
            if (!t.isString) {
                break
            }
            var negative = false
            var family = 0
            var prefix = 0
            val s = t.value
            var start = 0
            if (s!!.startsWith("!")) {
                negative = true
                start = 1
            }
            val colon = s.indexOf(':', start)
            if (colon < 0) {
                throw st.exception("invalid address prefix element")
            }
            val slash = s.indexOf('/', colon)
            if (slash < 0) {
                throw st.exception("invalid address prefix element")
            }
            val familyString = s.substring(start, colon)
            val addressString = s.substring(colon + 1, slash)
            val prefixString = s.substring(slash + 1)
            family = try {
                familyString.toInt()
            } catch (e: NumberFormatException) {
                throw st.exception("invalid family")
            }
            if (family != Address.IPv4 && family != Address.IPv6) {
                throw st.exception("unknown family")
            }
            prefix = try {
                prefixString.toInt()
            } catch (e: NumberFormatException) {
                throw st.exception("invalid prefix length")
            }
            if (!validatePrefixLength(family, prefix)) {
                throw st.exception("invalid prefix length")
            }
            var bytes: ByteArray? = null
            bytes = if (family == Address.IPv4) {
                IPv4.toBytesOrNull(addressString)
            } else {
                IPv6.toBytesOrNull(addressString)
            }
            if (bytes == null) {
                throw st.exception("invalid IP address $addressString")
            }
            val address = InetAddress.getByAddress(bytes)
            elements.add(Element(negative, address, prefix))
        }
        st.unget()
    }

    /**
     * Creates an APL Record from the given data.
     *
     * @param elements The list of APL elements.
     */
    constructor(name: Name, dclass: Int, ttl: Long, elements: List<Element>) : super(name, DnsRecordType.APL, dclass, ttl) {
        this.elements = ArrayList(elements.size)
        for (o: Any in elements) {
            require(o is Element) { "illegal element" }
            require(!(o.family != Address.IPv4 && o.family != Address.IPv6)) { "unknown family" }
            this.elements.add(o)
        }
    }

    /**
     * Returns the list of APL elements.
     */
    fun getElements(): List<Element> {
        return elements
    }

    companion object {
        private const val serialVersionUID = -1348173791712935864L
        private fun validatePrefixLength(family: Int, prefixLength: Int): Boolean {
            if (prefixLength < 0 || prefixLength >= 256) {
                return false
            }
            return !((family == Address.IPv4 && prefixLength > 32) || (family == Address.IPv6 && prefixLength > 128))
        }

        @Throws(WireParseException::class)
        private fun parseAddress(`in`: ByteArray, length: Int): ByteArray {
            if (`in`.size > length) {
                throw WireParseException("invalid address length")
            }
            if (`in`.size == length) {
                return `in`
            }
            val out = ByteArray(length)
            System.arraycopy(`in`, 0, out, 0, `in`.size)
            return out
        }

        private fun addressLength(addr: ByteArray): Int {
            for (i in addr.indices.reversed()) {
                if (addr[i].toInt() != 0) {
                    return i + 1
                }
            }
            return 0
        }
    }
}
