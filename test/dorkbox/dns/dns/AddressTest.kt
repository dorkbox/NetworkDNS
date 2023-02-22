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

import dorkbox.dns.dns.utils.Address.familyOf
import dorkbox.dns.dns.utils.Address.getAllByName
import dorkbox.dns.dns.utils.Address.getByName
import dorkbox.dns.dns.utils.Address.getHostName
import dorkbox.netUtil.IPv4
import dorkbox.netUtil.IPv4.isValid
import dorkbox.netUtil.IPv4.toBytes
import dorkbox.netUtil.IPv4.toInts
import dorkbox.netUtil.IPv4.toString
import dorkbox.netUtil.IPv6
import junit.framework.TestCase
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.*

class AddressTest : TestCase() {
    fun test_toByteArray_IPv4() {
        var exp = byteArrayOf(198.toByte(), 121.toByte(), 10.toByte(), 234.toByte())
        var ret = toBytes("198.121.10.234")
        assertEquals(exp, ret)

        exp = byteArrayOf(0, 0, 0, 0)
        ret = toBytes("0.0.0.0")
        assertEquals(exp, ret)

        exp = byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())
        ret = toBytes("255.255.255.255")
        assertEquals(exp, ret)
    }

    private fun assertEquals(exp: ByteArray?, act: ByteArray?) {
        assertTrue(Arrays.equals(exp, act))
    }

    fun test_toByteArray_IPv4_invalid() {
        assertNull(IPv4.toBytesOrNull("A.B.C.D"))
        assertNull(IPv4.toBytesOrNull("128..."))
        assertNull(IPv4.toBytesOrNull("128.121"))
        assertNull(IPv4.toBytesOrNull("128.111.8"))
        assertNull(IPv4.toBytesOrNull("128.198.10."))
        assertNull(IPv4.toBytesOrNull("128.121.90..10"))
        assertNull(IPv4.toBytesOrNull("128.121..90.10"))
        assertNull(IPv4.toBytesOrNull("128..121.90.10"))
        assertNull(IPv4.toBytesOrNull(".128.121.90.10"))
        assertNull(IPv4.toBytesOrNull("128.121.90.256"))
        assertNull(IPv4.toBytesOrNull("128.121.256.10"))
        assertNull(IPv4.toBytesOrNull("128.256.90.10"))
        assertNull(IPv4.toBytesOrNull("256.121.90.10"))
        assertNull(IPv4.toBytesOrNull("128.121.90.-1"))
        assertNull(IPv4.toBytesOrNull("128.121.-1.10"))
        assertNull(IPv4.toBytesOrNull("128.-1.90.10"))
        assertNull(IPv4.toBytesOrNull("-1.121.90.10"))
        assertNull(IPv4.toBytesOrNull("120.121.90.10.10"))

        // assertNull(IPv4.INSTANCE.toBytesOrNull("120.121.90.010")); // this is valid!
        // assertNull(IPv4.INSTANCE.toBytesOrNull("120.121.090.10")); // this is valid!
        // assertNull(IPv4.INSTANCE.toBytesOrNull("120.021.90.10")); // this is valid!
        // assertNull(IPv4.INSTANCE.toBytesOrNull("020.121.90.10")); // this is valid!
        assertNull(IPv4.toBytesOrNull("1120.121.90.10"))
        assertNull(IPv4.toBytesOrNull("120.2121.90.10"))
        assertNull(IPv4.toBytesOrNull("120.121.4190.10"))
        assertNull(IPv4.toBytesOrNull("120.121.190.1000"))
        assertNull(IPv4.toBytesOrNull(""))
    }

    fun test_toByteArray_IPv6() {
        var exp: ByteArray
        var ret: ByteArray?
        exp = byteArrayOf(
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
        ret = IPv6.toBytesOrNull("2001:0db8:85a3:08d3:1319:8a2e:0370:7334")
        assertEquals(exp, ret)

        ret = IPv6.toBytesOrNull("2001:db8:85a3:8d3:1319:8a2e:370:7334")
        assertEquals(exp, ret)

        ret = IPv6.toBytesOrNull("2001:DB8:85A3:8D3:1319:8A2E:370:7334")
        assertEquals(exp, ret)

        exp = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        ret = IPv6.toBytesOrNull("0:0:0:0:0:0:0:0")

        assertEquals(exp, ret)
        exp = byteArrayOf(
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte(),
            0xFF.toByte()
        )

        ret = IPv6.toBytesOrNull("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF")
        assertEquals(exp, ret)
        exp = byteArrayOf(
            32.toByte(),
            1.toByte(),
            13.toByte(),
            184.toByte(),
            0.toByte(),
            0.toByte(),
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

        ret = IPv6.toBytesOrNull("2001:0db8:0000:08d3:1319:8a2e:0370:7334")
        assertEquals(exp, ret)

        ret = IPv6.toBytesOrNull("2001:0db8::08d3:1319:8a2e:0370:7334")
        assertEquals(exp, ret)

        exp = byteArrayOf(
            0.toByte(),
            0.toByte(),
            0.toByte(),
            0.toByte(),
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
        ret = IPv6.toBytesOrNull("0000:0000:85a3:08d3:1319:8a2e:0370:7334")
        assertEquals(exp, ret)

        ret = IPv6.toBytesOrNull("::85a3:08d3:1319:8a2e:0370:7334")
        assertEquals(exp, ret)

        exp = byteArrayOf(
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
            0.toByte(),
            0.toByte(),
            0.toByte(),
            0.toByte()
        )
        ret = IPv6.toBytesOrNull("2001:0db8:85a3:08d3:1319:8a2e:0:0")
        assertEquals(exp, ret)

        ret = IPv6.toBytesOrNull("2001:0db8:85a3:08d3:1319:8a2e::")
        assertEquals(exp, ret)

        exp = byteArrayOf(
            32.toByte(),
            1.toByte(),
            13.toByte(),
            184.toByte(),
            0.toByte(),
            0.toByte(),
            0.toByte(),
            0.toByte(),
            0.toByte(),
            0.toByte(),
            0.toByte(),
            0.toByte(),
            3.toByte(),
            112.toByte(),
            115.toByte(),
            52.toByte()
        )
        ret = IPv6.toBytesOrNull("2001:0db8:0000:0000:0000:0000:0370:7334")
        assertEquals(exp, ret)

        ret = IPv6.toBytesOrNull("2001:0db8:0:0:0:0:0370:7334")
        assertEquals(exp, ret)

        ret = IPv6.toBytesOrNull("2001:0db8::0:0370:7334")
        assertEquals(exp, ret)

        ret = IPv6.toBytesOrNull("2001:db8::370:7334")
        assertEquals(exp, ret)

        exp = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1, -64, -88, 89, 9)
        ret = IPv6.toBytesOrNull("0000:0000:0000:0000:0000:0000:192.168.89.9")
        assertEquals(exp, ret)

        ret = IPv6.toBytesOrNull("2001:0db8:85a3:08d3:1319:0000:192.168.89.9")
        assertEquals(null, ret)

        exp = byteArrayOf(
            0.toByte(),
            0.toByte(),
            0.toByte(),
            0.toByte(),
            0.toByte(),
            0.toByte(),
            0.toByte(),
            0.toByte(),
            0.toByte(),
            0.toByte(),
            (-1.toByte()).toByte(),
            (-1.toByte()).toByte(),
            0xC0.toByte(),
            0xA8.toByte(),
            0x59.toByte(),
            0x09.toByte()
        )

        ret = IPv6.toBytesOrNull("::192.168.89.9")
        assertEquals(exp, ret)
    }

    fun test_toByteArray_IPv6_invalid() {
        // not enough groups
        assertNull(IPv6.toBytesOrNull("2001:0db8:85a3:08d3:1319:8a2e:0370"))
        // too many groups
        assertNull(IPv6.toBytesOrNull("2001:0db8:85a3:08d3:1319:8a2e:0370:193A:BCdE"))
        // invalid letter
        assertNull(IPv6.toBytesOrNull("2001:0gb8:85a3:08d3:1319:8a2e:0370:9819"))
        assertNull(IPv6.toBytesOrNull("lmno:0bb8:85a3:08d3:1319:8a2e:0370:9819"))
        assertNull(IPv6.toBytesOrNull("11ab:0ab8:85a3:08d3:1319:8a2e:0370:qrst"))
        // three consecutive colons
        assertNull(IPv6.toBytesOrNull("11ab:0ab8:85a3:08d3:::"))
        // IPv4 in the middle
        assertNull(IPv6.toBytesOrNull("2001:0ab8:192.168.0.1:1319:8a2e:0370:9819"))
        // invalid IPv4
        assertNull(IPv6.toBytesOrNull("2001:0ab8:1212:AbAb:8a2e:345.12.22.1"))
        // group with too many digits
        assertNull(IPv6.toBytesOrNull("2001:0ab8:85a3:128d3:1319:8a2e:0370:9819"))
    }

    fun test_toArray() {
        var exp = intArrayOf(1, 2, 3, 4)
        var ret = toInts("1.2.3.4")
        assertEquals(exp, ret)
        exp = intArrayOf(0, 0, 0, 0)
        ret = toInts("0.0.0.0")
        assertEquals(exp, ret)
        exp = intArrayOf(255, 255, 255, 255)
        ret = toInts("255.255.255.255")
        assertEquals(exp, ret)
    }

    private fun assertEquals(exp: IntArray, act: IntArray) {
        assertEquals(exp.size, act.size)
        for (i in exp.indices) {
            assertEquals("i=$i", exp[i], act[i])
        }
    }

    fun test_toArray_invalid() {
        assertNull(IPv4.toBytesOrNull("128.121.1"))
        assertNull(IPv4.toBytesOrNull(""))
    }

    fun test_isDottedQuad() {
        assertTrue(isValid("1.2.3.4"))
        assertFalse(isValid("256.2.3.4"))
    }

    fun test_toDottedQuad() {
        assertEquals("128.176.201.1", toString(byteArrayOf(128.toByte(), 176.toByte(), 201.toByte(), 1.toByte())))
        assertEquals("200.1.255.128", toString(intArrayOf(200, 1, 255, 128)))
    }

    fun test_addressLength() {
        assertEquals(4, IPv4.length)
        assertEquals(16, IPv6.length)
    }

    @Throws(UnknownHostException::class)
    fun test_getByName() {
        var out = getByName("128.145.198.231")
        assertEquals("128.145.198.231", out!!.hostAddress)
        out = getByName("a.root-servers.net")
        assertEquals("198.41.0.4", out!!.hostAddress)
    }

    @Throws(UnknownHostException::class)
    fun test_getByName_invalid() {
        assertNull(getByName("example.invalid"))

        try {
            val byName = getByName("")
            assertEquals("127.0.0.1", byName!!.hostAddress)
        } catch (ignored: UnknownHostException) {
            fail("UnknownHostException thrown")
        }
    }

    @Throws(UnknownHostException::class)
    fun test_getAllByName() {
        var out: Array<InetAddress?>
        out = getAllByName("128.145.198.231")
        assertEquals(1, out.size)
        assertEquals("128.145.198.231", out[0]!!.hostAddress)

        out = getAllByName("a.root-servers.net")
        assertTrue(out.size == 2)
        assertEquals("198.41.0.4", out[0]!!.hostAddress)
        assertEquals("2001:503:ba3e:0:0:0:2:30", out[1]!!.hostAddress)

        out = getAllByName("cnn.com")
        assertTrue(out.size > 1)
        for (i in out.indices) {
            val hostName = out[i]!!.hostName
            assertTrue(hostName.endsWith("cnn.com"))
        }
    }

    @Throws(UnknownHostException::class)
    fun test_getAllByName_invalid() {
        try {
            if (getAllByName("example.invalid").isNotEmpty()) {
                fail("getAllByName should be empty!")
            }
        } catch (ignored: UnknownHostException) {
        }

        try {
            val byName = getAllByName("")
            assertEquals("127.0.0.1", byName[0]!!.hostAddress)
            assertEquals("0:0:0:0:0:0:0:1", byName[1]!!.hostAddress)
        } catch (ignored: UnknownHostException) {
            ignored.printStackTrace()
            fail("${ignored.javaClass} thrown!")
        }
    }

    @Throws(UnknownHostException::class)
    fun test_familyOf() {
        assertTrue(IPv4.isFamily(InetAddress.getByName("192.168.0.1")))
        assertTrue(IPv6.isFamily(InetAddress.getByName("1:2:3:4:5:6:7:8")))

        try {
            familyOf(null)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
    }

    @Throws(UnknownHostException::class)
    fun test_getHostName() {
        val byName = InetAddress.getByName("198.41.0.4")
        val out = getHostName(byName)
        assertEquals("a.root-servers.net.", out)

        try {
            if (getHostName(InetAddress.getByName("192.168.1.1")) != null) {
                fail("getHostName should be null!")
            }
        } catch (ignored: UnknownHostException) {
        }
    }
}
