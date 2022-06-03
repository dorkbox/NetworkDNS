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
package dorkbox.dns.dns

import dorkbox.dns.dns.Name.Companion.fromString
import dorkbox.dns.dns.exceptions.TextParseException
import dorkbox.dns.dns.utils.Address
import dorkbox.dns.dns.utils.ReverseMap.fromAddress
import junit.framework.TestCase
import java.net.InetAddress
import java.net.UnknownHostException

class ReverseMapTest : TestCase() {
    @Throws(UnknownHostException::class, TextParseException::class)
    fun test_fromAddress_ipv4() {
        val exp = fromString("1.0.168.192.in-addr.arpa.")
        val addr = "192.168.0.1"
        assertEquals(exp, fromAddress(addr))
        assertEquals(exp, fromAddress(addr, Address.IPv4))
        assertEquals(exp, fromAddress(InetAddress.getByName(addr)))
        assertEquals(exp, fromAddress(byteArrayOf(192.toByte(), 168.toByte(), 0.toByte(), 1.toByte())))
        assertEquals(exp, fromAddress(intArrayOf(192, 168, 0, 1)))
    }

    @Throws(UnknownHostException::class, TextParseException::class)
    fun test_fromAddress_ipv6() {
        val exp = fromString("4.3.3.7.0.7.3.0.E.2.A.8.9.1.3.1.3.D.8.0.3.A.5.8.8.B.D.0.1.0.0.2.ip6.arpa.")
        val addr = "2001:0db8:85a3:08d3:1319:8a2e:0370:7334"
        val dat = byteArrayOf(
            32.toByte(),
            1.toByte(),
            13.toByte(),
            184.toByte(),
            133.toByte(),
            163.toByte(),
            8.toByte(),
            211.toByte(),
            19.toByte(),
            25.toByte(),
            138.toByte(),
            46.toByte(),
            3.toByte(),
            112.toByte(),
            115.toByte(),
            52.toByte()
        )
        val idat = intArrayOf(32, 1, 13, 184, 133, 163, 8, 211, 19, 25, 138, 46, 3, 112, 115, 52)
        assertEquals(exp, fromAddress(addr, Address.IPv6))
        assertEquals(exp, fromAddress(InetAddress.getByName(addr)))
        assertEquals(exp, fromAddress(dat))
        assertEquals(exp, fromAddress(idat))
    }

    fun test_fromAddress_invalid() {
        try {
            fromAddress("A.B.C.D", Address.IPv4)
            fail("UnknownHostException not thrown")
        } catch (ignored: UnknownHostException) {
        }

        try {
            fromAddress(ByteArray(0))
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }

        try {
            fromAddress(ByteArray(3))
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }

        try {
            fromAddress(ByteArray(5))
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }

        try {
            fromAddress(ByteArray(15))
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }

        try {
            fromAddress(ByteArray(17))
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }

        try {
            val dat = intArrayOf(0, 1, 2, 256)
            fromAddress(dat)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
    }
}
