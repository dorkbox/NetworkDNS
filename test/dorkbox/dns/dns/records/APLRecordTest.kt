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
import dorkbox.dns.dns.Name
import dorkbox.dns.dns.Name.Companion.fromString
import dorkbox.dns.dns.constants.DnsClass
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.exceptions.RelativeNameException
import dorkbox.dns.dns.exceptions.TextParseException
import dorkbox.dns.dns.exceptions.WireParseException
import dorkbox.dns.dns.utils.Address
import dorkbox.dns.dns.utils.Tokenizer
import junit.framework.Test
import junit.framework.TestCase
import junit.framework.TestSuite
import java.io.IOException
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.*

object APLRecordTest {
    fun suite(): Test {
        val s = TestSuite()
        s.addTestSuite(Test_Element_init::class.java)
        s.addTestSuite(Test_init::class.java)
        s.addTestSuite(Test_rrFromWire::class.java)
        s.addTestSuite(Test_rdataFromString::class.java)
        s.addTestSuite(Test_rrToString::class.java)
        s.addTestSuite(Test_rrToWire::class.java)
        return s
    }

    class Test_Element_init : TestCase() {
        lateinit var m_addr4: InetAddress
        lateinit var m_addr6: InetAddress

        @Throws(TextParseException::class, UnknownHostException::class)
        override fun setUp() {
            m_addr4 = InetAddress.getByName("193.160.232.5")
            m_addr6 = InetAddress.getByName("2001:db8:85a3:8d3:1319:8a2e:370:7334")
        }

        fun test_valid_IPv4() {
            val el = APLRecord.Element(true, m_addr4, 16)
            assertEquals(Address.IPv4, el.family)
            assertEquals(true, el.negative)
            assertEquals(m_addr4, el.address)
            assertEquals(16, el.prefixLength)
        }

        fun test_invalid_IPv4() {
            try {
                APLRecord.Element(true, m_addr4, 33)
                fail("IllegalArgumentException not thrown")
            } catch (ignored: IllegalArgumentException) {
            }
        }

        fun test_valid_IPv6() {
            val el = APLRecord.Element(false, m_addr6, 74)
            assertEquals(Address.IPv6, el.family)
            assertEquals(false, el.negative)
            assertEquals(m_addr6, el.address)
            assertEquals(74, el.prefixLength)
        }

        fun test_invalid_IPv6() {
            try {
                APLRecord.Element(true, m_addr6, 129)
                fail("IllegalArgumentException not thrown")
            } catch (ignored: IllegalArgumentException) {
            }
        }
    }

    class Test_init : TestCase() {
        lateinit var m_an: Name
        lateinit var m_rn: Name
        var m_ttl: Long = 0
        lateinit var m_elements: ArrayList<APLRecord.Element>
        lateinit var m_addr4: InetAddress
        lateinit var m_addr4_string: String
        lateinit var m_addr4_bytes: ByteArray
        lateinit var m_addr6: InetAddress
        lateinit var m_addr6_string: String
        lateinit var m_addr6_bytes: ByteArray

        @Throws(UnknownHostException::class)
        fun test_0arg() {
            val ar = APLRecord()
            try {
                // name isn't initialized yet!
                assertNull(ar.name)
                fail("Name should not be initialized!")
            } catch (ignored: Exception) {
            }
            assertEquals(0, ar.type)
            assertEquals(0, ar.dclass)
            assertEquals(0, ar.ttl)
            try {
                // name isn't initialized yet!
                assertNull(ar.getElements())
                fail("Name should not be initialized!")
            } catch (ignored: Exception) {
            }
        }

        fun test_getObject() {
            val ar = APLRecord()
            val r = ar.dnsRecord
            assertTrue(r is APLRecord)
        }

        @Throws(TextParseException::class, UnknownHostException::class)
        override fun setUp() {
            m_an = fromString("My.Absolute.Name.")
            m_rn = fromString("My.Relative.Name")
            m_ttl = 0x13579
            m_addr4_string = "193.160.232.5"
            m_addr4 = InetAddress.getByName(m_addr4_string)
            m_addr4_bytes = m_addr4.getAddress()
            m_addr6_string = "2001:db8:85a3:8d3:1319:8a2e:370:7334"
            m_addr6 = InetAddress.getByName(m_addr6_string)
            m_addr6_bytes = m_addr6.getAddress()
            m_elements = ArrayList(2)
            var e = APLRecord.Element(true, m_addr4, 12)
            m_elements.add(e)
            e = APLRecord.Element(false, m_addr6, 64)
            m_elements.add(e)
        }

        fun test_4arg_basic() {
            val ar = APLRecord(m_an, DnsClass.IN, m_ttl, m_elements)
            assertEquals(m_an, ar.name)
            assertEquals(DnsRecordType.APL, ar.type)
            assertEquals(DnsClass.IN, ar.dclass)
            assertEquals(m_ttl, ar.ttl)
            assertEquals(m_elements, ar.getElements())
        }

        fun test_4arg_empty_elements() {
            val ar = APLRecord(m_an, DnsClass.IN, m_ttl, ArrayList())
            assertEquals(ArrayList<APLRecord.Element>(), ar.getElements())
        }

        fun test_4arg_relative_name() {
            try {
                APLRecord(m_rn, DnsClass.IN, m_ttl, m_elements)
                fail("RelativeNameException not thrown")
            } catch (ignored: RelativeNameException) {
            }
        }

        fun test_4arg_invalid_elements() {
            m_elements = ArrayList()
            // this is on purpose!
            (m_elements as MutableList<Int>).add(5)

            try {
                APLRecord(m_an, DnsClass.IN, m_ttl, m_elements)
                fail("IllegalArgumentException not thrown")
            } catch (ignored: IllegalArgumentException) {
            }
        }
    }

    class Test_rrFromWire : TestCase() {
        lateinit var m_addr4: InetAddress
        lateinit var m_addr4_bytes: ByteArray
        lateinit var m_addr6: InetAddress
        lateinit var m_addr6_bytes: ByteArray

        @Throws(IOException::class)
        fun test_validIPv4() {
            val raw = byteArrayOf(0, 1, 8, 0x84.toByte(), m_addr4_bytes[0], m_addr4_bytes[1], m_addr4_bytes[2], m_addr4_bytes[3])
            val di = DnsInput(raw)
            val ar = APLRecord()
            ar.rrFromWire(di)
            val exp = ArrayList<APLRecord.Element>()
            exp.add(APLRecord.Element(true, m_addr4, 8))
            assertEquals(exp, ar.getElements())
        }

        @Throws(IOException::class)
        fun test_validIPv4_short_address() {
            val raw = byteArrayOf(0, 1, 20, 0x83.toByte(), m_addr4_bytes[0], m_addr4_bytes[1], m_addr4_bytes[2])
            val di = DnsInput(raw)
            val ar = APLRecord()
            ar.rrFromWire(di)
            val a = InetAddress.getByName("193.160.232.0")
            val exp = ArrayList<APLRecord.Element>()
            exp.add(APLRecord.Element(true, a, 20))
            assertEquals(exp, ar.getElements())
        }

        @Throws(TextParseException::class, UnknownHostException::class)
        override fun setUp() {
            m_addr4 = InetAddress.getByName("193.160.232.5")
            m_addr4_bytes = m_addr4.getAddress()
            m_addr6 = InetAddress.getByName("2001:db8:85a3:8d3:1319:8a2e:370:7334")
            m_addr6_bytes = m_addr6.getAddress()
        }

        @Throws(IOException::class)
        fun test_invalid_IPv4_prefix() {
            val raw = byteArrayOf(0, 1, 33, 0x84.toByte(), m_addr4_bytes[0], m_addr4_bytes[1], m_addr4_bytes[2], m_addr4_bytes[3])
            val di = DnsInput(raw)
            val ar = APLRecord()
            try {
                ar.rrFromWire(di)
                fail("WireParseException not thrown")
            } catch (ignored: WireParseException) {
            }
        }

        @Throws(IOException::class)
        fun test_invalid_IPv4_length() {
            val raw = byteArrayOf(0, 1, 8, 0x85.toByte(), m_addr4_bytes[0], m_addr4_bytes[1], m_addr4_bytes[2], m_addr4_bytes[3], 10)
            val di = DnsInput(raw)
            val ar = APLRecord()
            try {
                ar.rrFromWire(di)
                fail("WireParseException not thrown")
            } catch (ignored: WireParseException) {
            }
        }

        @Throws(IOException::class)
        fun test_multiple_validIPv4() {
            val raw = byteArrayOf(
                0,
                1,
                8,
                0x84.toByte(),
                m_addr4_bytes[0],
                m_addr4_bytes[1],
                m_addr4_bytes[2],
                m_addr4_bytes[3],
                0,
                1,
                30,
                0x4.toByte(),
                m_addr4_bytes[0],
                m_addr4_bytes[1],
                m_addr4_bytes[2],
                m_addr4_bytes[3]
            )
            val di = DnsInput(raw)
            val ar = APLRecord()
            ar.rrFromWire(di)
            val exp = ArrayList<APLRecord.Element>()
            exp.add(APLRecord.Element(true, m_addr4, 8))
            exp.add(APLRecord.Element(false, m_addr4, 30))
            assertEquals(exp, ar.getElements())
        }

        @Throws(IOException::class)
        fun test_validIPv6() {
            val raw = byteArrayOf(
                0,
                2,
                115.toByte(),
                0x10.toByte(),
                m_addr6_bytes[0],
                m_addr6_bytes[1],
                m_addr6_bytes[2],
                m_addr6_bytes[3],
                m_addr6_bytes[4],
                m_addr6_bytes[5],
                m_addr6_bytes[6],
                m_addr6_bytes[7],
                m_addr6_bytes[8],
                m_addr6_bytes[9],
                m_addr6_bytes[10],
                m_addr6_bytes[11],
                m_addr6_bytes[12],
                m_addr6_bytes[13],
                m_addr6_bytes[14],
                m_addr6_bytes[15]
            )
            val di = DnsInput(raw)
            val ar = APLRecord()
            ar.rrFromWire(di)
            val exp = ArrayList<APLRecord.Element>()
            exp.add(APLRecord.Element(false, m_addr6, 115))
            assertEquals(exp, ar.getElements())
        }

        @Throws(IOException::class)
        fun test_valid_nonIP() {
            val raw = byteArrayOf(0, 3, 130.toByte(), 0x85.toByte(), 1, 2, 3, 4, 5)
            val di = DnsInput(raw)
            val ar = APLRecord()
            ar.rrFromWire(di)
            val l = ar.getElements()
            assertEquals(1, l.size)
            val el = l[0]
            assertEquals(3, el.family)
            assertEquals(true, el.negative)
            assertEquals(130, el.prefixLength)
            assertTrue(Arrays.equals(byteArrayOf(1, 2, 3, 4, 5), el.address as ByteArray))
        }
    }

    class Test_rdataFromString : TestCase() {
        lateinit var m_addr4: InetAddress
        lateinit var m_addr4_string: String
        lateinit var m_addr4_bytes: ByteArray
        lateinit var m_addr6: InetAddress
        lateinit var m_addr6_string: String
        lateinit var m_addr6_bytes: ByteArray

        @Throws(IOException::class)
        fun test_validIPv4() {
            val t = Tokenizer("1:$m_addr4_string/11\n")
            val ar = APLRecord()
            ar.rdataFromString(t, null)
            val exp = ArrayList<APLRecord.Element>()
            exp.add(APLRecord.Element(false, m_addr4, 11))
            assertEquals(exp, ar.getElements())

            // make sure extra token is put back
            assertEquals(Tokenizer.EOL, t.get().type)
        }

        @Throws(IOException::class)
        fun test_valid_multi() {
            val t = Tokenizer("1:$m_addr4_string/11 !2:$m_addr6_string/100")
            val ar = APLRecord()
            ar.rdataFromString(t, null)
            val exp = ArrayList<APLRecord.Element>()
            exp.add(APLRecord.Element(false, m_addr4, 11))
            exp.add(APLRecord.Element(true, m_addr6, 100))
            assertEquals(exp, ar.getElements())
        }

        @Throws(TextParseException::class, UnknownHostException::class)
        override fun setUp() {
            m_addr4_string = "193.160.232.5"
            m_addr4 = InetAddress.getByName(m_addr4_string)
            m_addr4_bytes = m_addr4.getAddress()
            m_addr6_string = "2001:db8:85a3:8d3:1319:8a2e:370:7334"
            m_addr6 = InetAddress.getByName(m_addr6_string)
            m_addr6_bytes = m_addr6.getAddress()
        }

        @Throws(IOException::class)
        fun test_validIPv6() {
            val t = Tokenizer("!2:$m_addr6_string/36\n")
            val ar = APLRecord()
            ar.rdataFromString(t, null)
            val exp = ArrayList<APLRecord.Element>()
            exp.add(APLRecord.Element(true, m_addr6, 36))
            assertEquals(exp, ar.getElements())

            // make sure extra token is put back
            assertEquals(Tokenizer.EOL, t.get().type)
        }

        @Throws(IOException::class)
        fun test_no_colon() {
            val t = Tokenizer("!1192.68.0.1/20")
            val ar = APLRecord()
            try {
                ar.rdataFromString(t, null)
                fail("TextParseException not thrown")
            } catch (ignored: TextParseException) {
            }
        }

        @Throws(IOException::class)
        fun test_colon_and_slash_swapped() {
            val t = Tokenizer("!1/192.68.0.1:20")
            val ar = APLRecord()
            try {
                ar.rdataFromString(t, null)
                fail("TextParseException not thrown")
            } catch (ignored: TextParseException) {
            }
        }

        @Throws(IOException::class)
        fun test_no_slash() {
            val t = Tokenizer("!1:192.68.0.1|20")
            val ar = APLRecord()
            try {
                ar.rdataFromString(t, null)
                fail("TextParseException not thrown")
            } catch (ignored: TextParseException) {
            }
        }

        @Throws(IOException::class)
        fun test_empty_family() {
            val t = Tokenizer("!:192.68.0.1/20")
            val ar = APLRecord()
            try {
                ar.rdataFromString(t, null)
                fail("TextParseException not thrown")
            } catch (ignored: TextParseException) {
            }
        }

        @Throws(IOException::class)
        fun test_malformed_family() {
            val t = Tokenizer("family:192.68.0.1/20")
            val ar = APLRecord()
            try {
                ar.rdataFromString(t, null)
                fail("TextParseException not thrown")
            } catch (ignored: TextParseException) {
            }
        }

        @Throws(IOException::class)
        fun test_invalid_family() {
            val t = Tokenizer("3:192.68.0.1/20")
            val ar = APLRecord()
            try {
                ar.rdataFromString(t, null)
                fail("TextParseException not thrown")
            } catch (ignored: TextParseException) {
            }
        }

        @Throws(IOException::class)
        fun test_empty_prefix() {
            val t = Tokenizer("1:192.68.0.1/")
            val ar = APLRecord()
            try {
                ar.rdataFromString(t, null)
                fail("TextParseException not thrown")
            } catch (ignored: TextParseException) {
            }
        }

        @Throws(IOException::class)
        fun test_malformed_prefix() {
            val t = Tokenizer("1:192.68.0.1/prefix")
            val ar = APLRecord()
            try {
                ar.rdataFromString(t, null)
                fail("TextParseException not thrown")
            } catch (ignored: TextParseException) {
            }
        }

        @Throws(IOException::class)
        fun test_invalid_prefix() {
            val t = Tokenizer("1:192.68.0.1/33")
            val ar = APLRecord()
            try {
                ar.rdataFromString(t, null)
                fail("TextParseException not thrown")
            } catch (ignored: TextParseException) {
            }
        }

        @Throws(IOException::class)
        fun test_empty_address() {
            val t = Tokenizer("1:/33")
            val ar = APLRecord()
            try {
                ar.rdataFromString(t, null)
                fail("TextParseException not thrown")
            } catch (ignored: TextParseException) {
            }
        }

        @Throws(IOException::class)
        fun test_malformed_address() {
            val t = Tokenizer("1:A.B.C.D/33")
            val ar = APLRecord()
            try {
                ar.rdataFromString(t, null)
                fail("TextParseException not thrown")
            } catch (ignored: TextParseException) {
            }
        }
    }

    class Test_rrToString : TestCase() {
        lateinit var m_an: Name
        lateinit var m_rn: Name
        var m_ttl: Long = 0
        lateinit var m_elements: ArrayList<APLRecord.Element>
        lateinit var m_addr4: InetAddress
        lateinit var m_addr4_string: String
        lateinit var m_addr4_bytes: ByteArray
        lateinit var m_addr6: InetAddress
        lateinit var m_addr6_string: String
        lateinit var m_addr6_bytes: ByteArray

        fun test() {
            val ar = APLRecord(m_an, DnsClass.IN, m_ttl, m_elements)
            val sb = StringBuilder()
            ar.rrToString(sb)
            assertEquals("!1:$m_addr4_string/12 2:$m_addr6_string/64", sb.toString())
        }

        @Throws(TextParseException::class, UnknownHostException::class)
        override fun setUp() {
            m_an = fromString("My.Absolute.Name.")
            m_rn = fromString("My.Relative.Name")
            m_ttl = 0x13579
            m_addr4_string = "193.160.232.5"
            m_addr4 = InetAddress.getByName(m_addr4_string)
            m_addr4_bytes = m_addr4.getAddress()
            m_addr6_string = "2001:db8:85a3:8d3:1319:8a2e:370:7334"
            m_addr6 = InetAddress.getByName(m_addr6_string)
            m_addr6_bytes = m_addr6.getAddress()
            m_elements = ArrayList(2)
            var e = APLRecord.Element(true, m_addr4, 12)
            m_elements.add(e)
            e = APLRecord.Element(false, m_addr6, 64)
            m_elements.add(e)
        }
    }

    class Test_rrToWire : TestCase() {
        lateinit var m_an: Name
        lateinit var m_rn: Name
        var m_ttl: Long = 0
        lateinit var m_elements: ArrayList<APLRecord.Element>
        lateinit var m_addr4: InetAddress
        lateinit var m_addr4_string: String
        lateinit var m_addr4_bytes: ByteArray
        lateinit var m_addr6: InetAddress
        lateinit var m_addr6_string: String
        lateinit var m_addr6_bytes: ByteArray

        fun test_empty() {
            val ar = APLRecord(m_an, DnsClass.IN, m_ttl, ArrayList())
            val dout = DnsOutput()
            ar.rrToWire(dout, null, true)
            assertTrue(Arrays.equals(ByteArray(0), dout.toByteArray()))
        }

        fun test_basic() {
            val ar = APLRecord(m_an, DnsClass.IN, m_ttl, m_elements)
            val exp = byteArrayOf(
                0,
                1,
                12,
                0x84.toByte(),
                m_addr4_bytes[0],
                m_addr4_bytes[1],
                m_addr4_bytes[2],
                m_addr4_bytes[3],
                0,
                2,
                64,
                0x10,
                m_addr6_bytes[0],
                m_addr6_bytes[1],
                m_addr6_bytes[2],
                m_addr6_bytes[3],
                m_addr6_bytes[4],
                m_addr6_bytes[5],
                m_addr6_bytes[6],
                m_addr6_bytes[7],
                m_addr6_bytes[8],
                m_addr6_bytes[9],
                m_addr6_bytes[10],
                m_addr6_bytes[11],
                m_addr6_bytes[12],
                m_addr6_bytes[13],
                m_addr6_bytes[14],
                m_addr6_bytes[15]
            )
            val dout = DnsOutput()
            ar.rrToWire(dout, null, true)
            assertTrue(Arrays.equals(exp, dout.toByteArray()))
        }

        @Throws(TextParseException::class, UnknownHostException::class)
        override fun setUp() {
            m_an = fromString("My.Absolute.Name.")
            m_rn = fromString("My.Relative.Name")
            m_ttl = 0x13579
            m_addr4_string = "193.160.232.5"
            m_addr4 = InetAddress.getByName(m_addr4_string)
            m_addr4_bytes = m_addr4.getAddress()
            m_addr6_string = "2001:db8:85a3:8d3:1319:8a2e:370:7334"
            m_addr6 = InetAddress.getByName(m_addr6_string)
            m_addr6_bytes = m_addr6.getAddress()
            m_elements = ArrayList(2)
            var e = APLRecord.Element(true, m_addr4, 12)
            m_elements.add(e)
            e = APLRecord.Element(false, m_addr6, 64)
            m_elements.add(e)
        }

        @Throws(IOException::class)
        fun test_non_IP() {
            val exp = byteArrayOf(0, 3, 130.toByte(), 0x85.toByte(), 1, 2, 3, 4, 5)
            val di = DnsInput(exp)
            val ar = APLRecord()
            ar.rrFromWire(di)
            val dout = DnsOutput()
            ar.rrToWire(dout, null, true)
            assertTrue(Arrays.equals(exp, dout.toByteArray()))
        }

        @Throws(UnknownHostException::class)
        fun test_address_with_embedded_zero() {
            val a = InetAddress.getByName("232.0.11.1")
            val elements = ArrayList<APLRecord.Element>()
            elements.add(APLRecord.Element(true, a, 31))
            val ar = APLRecord(m_an, DnsClass.IN, m_ttl, elements)
            val exp = byteArrayOf(0, 1, 31, 0x84.toByte(), 232.toByte(), 0, 11, 1)
            val dout = DnsOutput()
            ar.rrToWire(dout, null, true)
            assertTrue(Arrays.equals(exp, dout.toByteArray()))
        }

        @Throws(UnknownHostException::class)
        fun test_short_address() {
            val a = InetAddress.getByName("232.0.11.0")
            val elements = ArrayList<APLRecord.Element>()
            elements.add(APLRecord.Element(true, a, 31))
            val ar = APLRecord(m_an, DnsClass.IN, m_ttl, elements)
            val exp = byteArrayOf(0, 1, 31, 0x83.toByte(), 232.toByte(), 0, 11)
            val dout = DnsOutput()
            ar.rrToWire(dout, null, true)
            assertTrue(Arrays.equals(exp, dout.toByteArray()))
        }

        @Throws(UnknownHostException::class)
        fun test_wildcard_address() {
            val a = InetAddress.getByName("0.0.0.0")
            val elements = ArrayList<APLRecord.Element>()
            elements.add(APLRecord.Element(true, a, 31))
            val ar = APLRecord(m_an, DnsClass.IN, m_ttl, elements)
            val exp = byteArrayOf(0, 1, 31, 0x80.toByte())
            val dout = DnsOutput()
            ar.rrToWire(dout, null, true)
            assertTrue(Arrays.equals(exp, dout.toByteArray()))
        }
    }
}
