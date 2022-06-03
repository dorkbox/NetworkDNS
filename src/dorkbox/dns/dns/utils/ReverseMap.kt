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
package dorkbox.dns.dns.utils

import dorkbox.dns.dns.Name
import dorkbox.dns.dns.exceptions.TextParseException
import dorkbox.netUtil.IPv4
import dorkbox.netUtil.IPv6
import java.net.InetAddress
import java.net.UnknownHostException

/**
 * A set functions designed to deal with DNS names used in reverse mappings.
 * For the IPv4 address a.b.c.d, the reverse map name is d.c.b.a.in-addr.arpa.
 * For an IPv6 address, the reverse map name is ...ip6.arpa.
 *
 * @author Brian Wellington
 */
object ReverseMap {
    private val inaddr4 = Name.fromConstantString("in-addr.arpa.")
    private val inaddr6 = Name.fromConstantString("ip6.arpa.")

    /**
     * Creates a reverse map name corresponding to an address contained in
     * an array of 4 integers between 0 and 255 (for an IPv4 address) or 16
     * integers between 0 and 255 (for an IPv6 address).
     *
     * @param addr The address from which to build a name.
     *
     * @return The name corresponding to the address in the reverse map.
     */
    fun fromAddress(addr: IntArray): Name {
        val bytes = ByteArray(addr.size)
        for (i in addr.indices) {
            require(!(addr[i] < 0 || addr[i] > 0xFF)) { "array must " + "contain values " + "between 0 and 255" }
            bytes[i] = addr[i].toByte()
        }
        return fromAddress(bytes)
    }

    /**
     * Creates a reverse map name corresponding to an address contained in
     * an array of 4 bytes (for an IPv4 address) or 16 bytes (for an IPv6 address).
     *
     * @param addr The address from which to build a name.
     *
     * @return The name corresponding to the address in the reverse map.
     */
    fun fromAddress(addr: ByteArray): Name {
        require(!(addr.size != 4 && addr.size != 16)) { "array must contain " + "4 or 16 elements" }
        val sb = StringBuilder()
        if (addr.size == 4) {
            for (i in addr.indices.reversed()) {
                sb.append(addr[i].toInt() and 0xFF)
                if (i > 0) {
                    sb.append(".")
                }
            }
        } else {
            val nibbles = IntArray(2)
            for (i in addr.indices.reversed()) {
                nibbles[0] = addr[i].toInt() and 0xFF shr 4
                nibbles[1] = addr[i].toInt() and 0xFF and 0xF
                for (j in nibbles.indices.reversed()) {
                    sb.append(Integer.toHexString(nibbles[j]))
                    if (i > 0 || j > 0) {
                        sb.append(".")
                    }
                }
            }
        }
        return try {
            if (addr.size == 4) {
                Name.Companion.fromString(sb.toString(), inaddr4)
            } else {
                Name.Companion.fromString(sb.toString(), inaddr6)
            }
        } catch (e: TextParseException) {
            throw IllegalStateException("name cannot be invalid")
        }
    }

    /**
     * Creates a reverse map name corresponding to an address contained in
     * an InetAddress.
     *
     * @param addr The address from which to build a name.
     *
     * @return The name corresponding to the address in the reverse map.
     */
    fun fromAddress(addr: InetAddress): Name {
        return fromAddress(addr.address)
    }

    /**
     * Creates a reverse map name corresponding to an address contained in
     * a String.
     *
     * @param addr The address from which to build a name.
     *
     * @return The name corresponding to the address in the reverse map.
     *
     * @throws UnknownHostException The string does not contain a valid address.
     */
    @Throws(UnknownHostException::class)
    fun fromAddress(addr: String?, family: Int): Name {
        if (family == Address.IPv4 && IPv4.isValid(addr!!)) {
            return fromAddress(IPv4.toBytes(addr))
        } else if (family == Address.IPv6 && IPv6.isValid(addr!!)) {
            return fromAddress(IPv6.toBytes(addr))
        }
        throw UnknownHostException("Invalid IP address")
    }

    /**
     * Creates a reverse map name corresponding to an address contained in
     * a String.
     *
     * @param addr The address from which to build a name.
     *
     * @return The name corresponding to the address in the reverse map.
     *
     * @throws UnknownHostException The string does not contain a valid address.
     */
    @Throws(UnknownHostException::class)
    fun fromAddress(addr: String?): Name {
        var array: ByteArray? = null
        if (IPv4.isValid(addr!!)) {
            array = IPv4.toBytes(addr)
        } else if (IPv6.isValid(addr)) {
            array = IPv6.toBytes(addr)
        }
        if (array == null) {
            throw UnknownHostException("Invalid IP address")
        }
        return fromAddress(array)
    }
}
