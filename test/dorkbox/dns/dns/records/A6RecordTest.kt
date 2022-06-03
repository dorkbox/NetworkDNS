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
import dorkbox.dns.dns.utils.Tokenizer
import junit.framework.TestCase
import java.io.IOException
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.*

class A6RecordTest : TestCase() {
    lateinit var m_an: Name
    lateinit var m_an2: Name
    lateinit var m_rn: Name
    lateinit var m_addr: InetAddress
    lateinit var m_addr_string: String
    lateinit var m_addr_string_canonical: String
    lateinit var m_addr_bytes: ByteArray
    var m_prefix_bits = 0
    var m_ttl: Long = 0
    
    @Throws(TextParseException::class, UnknownHostException::class)
    override fun setUp() {
        m_an = fromString("My.Absolute.Name.")
        m_an2 = fromString("My.Second.Absolute.Name.")
        m_rn = fromString("My.Relative.Name")
        m_addr_string = "2001:0db8:85a3:08d3:1319:8a2e:0370:7334"
        m_addr_string_canonical = "2001:db8:85a3:8d3:1319:8a2e:370:7334"
        m_addr = InetAddress.getByName(m_addr_string)
        m_addr_bytes = m_addr.getAddress()
        m_ttl = 0x13579
        m_prefix_bits = 9
    }

    fun test_ctor_0arg() {
        val ar = A6Record()
        try {
            // name isn't initialized yet!
            assertNull(ar.name)
            fail("Name should not be initialized!")
        } catch (ignored: Exception) {
        }
        assertEquals(0, ar.type)
        assertEquals(0, ar.dclass)
        assertEquals(0, ar.ttl)
    }

    fun test_getObject() {
        val ar = A6Record()
        val r = ar.`object`
        assertTrue(r is A6Record)
    }

    fun test_ctor_6arg() {
        var ar = A6Record(m_an, DnsClass.IN, m_ttl, m_prefix_bits, m_addr, null)
        assertEquals(m_an, ar.name)
        assertEquals(DnsRecordType.A6, ar.type)
        assertEquals(DnsClass.IN, ar.dclass)
        assertEquals(m_ttl, ar.ttl)
        assertEquals(m_prefix_bits, ar.prefixBits)
        assertEquals(m_addr, ar.suffix)
        assertNull(ar.prefix)

        // with the prefix name
        ar = A6Record(m_an, DnsClass.IN, m_ttl, m_prefix_bits, m_addr, m_an2)
        assertEquals(m_an, ar.name)
        assertEquals(DnsRecordType.A6, ar.type)
        assertEquals(DnsClass.IN, ar.dclass)
        assertEquals(m_ttl, ar.ttl)
        assertEquals(m_prefix_bits, ar.prefixBits)
        assertEquals(m_addr, ar.suffix)
        assertEquals(m_an2, ar.prefix)

        // a relative name
        try {
            A6Record(m_rn, DnsClass.IN, m_ttl, m_prefix_bits, m_addr, null)
            fail("RelativeNameException not thrown")
        } catch (ignored: RelativeNameException) {
        }

        // a relative prefix name
        try {
            A6Record(m_an, DnsClass.IN, m_ttl, m_prefix_bits, m_addr, m_rn)
            fail("RelativeNameException not thrown")
        } catch (ignored: RelativeNameException) {
        }

        // invalid prefix bits
        try {
            A6Record(m_rn, DnsClass.IN, m_ttl, 0x100, m_addr, null)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: RelativeNameException) {
        }

        // an IPv4 address
        try {
            A6Record(m_an, DnsClass.IN, m_ttl, m_prefix_bits, InetAddress.getByName("192.168.0.1"), null)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        } catch (e: UnknownHostException) {
            fail(e.message)
        }
    }

    @Throws(CloneNotSupportedException::class, IOException::class, UnknownHostException::class)
    fun test_rrFromWire() {
        // record with no prefix
        var dout = DnsOutput()
        dout.writeU8(0)
        dout.writeByteArray(m_addr_bytes)
        var din = DnsInput(dout.toByteArray())
        var ar = A6Record()
        ar.rrFromWire(din)
        assertEquals(0, ar.prefixBits)
        assertEquals(m_addr, ar.suffix)
        assertNull(ar.prefix)

        // record with 9 bit prefix (should result in 15 bytes of the address)
        dout = DnsOutput()
        dout.writeU8(9)
        dout.writeByteArray(m_addr_bytes, 1, 15)
        dout.writeByteArray(m_an2.toWire())
        din = DnsInput(dout.toByteArray())
        ar = A6Record()
        ar.rrFromWire(din)
        assertEquals(9, ar.prefixBits)
        val addr_bytes = m_addr_bytes.clone()
        addr_bytes[0] = 0
        val exp = InetAddress.getByAddress(addr_bytes)
        assertEquals(exp, ar.suffix)
        assertEquals(m_an2, ar.prefix)
    }

    @Throws(CloneNotSupportedException::class, IOException::class, UnknownHostException::class)
    fun test_rdataFromString() {
        // record with no prefix
        var t = Tokenizer("0 $m_addr_string")
        var ar = A6Record()
        ar.rdataFromString(t, null)
        assertEquals(0, ar.prefixBits)
        assertEquals(m_addr, ar.suffix)
        assertNull(ar.prefix)

        // record with 9 bit prefix.  In contrast to the rrFromWire method,
        // rdataFromString expects the entire 128 bits to be represented
        // in the string
        t = Tokenizer("9 $m_addr_string $m_an2")
        ar = A6Record()
        ar.rdataFromString(t, null)
        assertEquals(9, ar.prefixBits)
        assertEquals(m_addr, ar.suffix)
        assertEquals(m_an2, ar.prefix)

        // record with invalid prefixBits
        t = Tokenizer("129")
        ar = A6Record()
        try {
            ar.rdataFromString(t, null)
            fail("TextParseException not thrown")
         } catch (ignored: TextParseException) {
        }

        // record with invalid ipv6 address
        t = Tokenizer("0 " + m_addr_string.substring(4))
        ar = A6Record()
        try {
            ar.rdataFromString(t, null)
            fail("TextParseException not thrown")
         } catch (ignored: TextParseException) {
        }
    }

    fun test_rrToString() {
        val ar = A6Record(m_an, DnsClass.IN, m_ttl, m_prefix_bits, m_addr, m_an2)
        val exp = "$m_prefix_bits $m_addr_string_canonical $m_an2"
        val stringBuilder = StringBuilder()
        ar.rrToString(stringBuilder)
        val out = stringBuilder.toString()
        assertEquals(exp, out)
    }

    fun test_rrToWire() {
        // canonical form
        val ar = A6Record(m_an, DnsClass.IN, m_ttl, m_prefix_bits, m_addr, m_an2)
        var dout = DnsOutput()
        dout.writeU8(m_prefix_bits)
        dout.writeByteArray(m_addr_bytes, 1, 15)
        dout.writeByteArray(m_an2.toWireCanonical())
        var exp = dout.toByteArray()
        dout = DnsOutput()
        ar.rrToWire(dout, null, true)
        assertTrue(Arrays.equals(exp, dout.toByteArray()))

        // case sensitiveform
        dout = DnsOutput()
        dout.writeU8(m_prefix_bits)
        dout.writeByteArray(m_addr_bytes, 1, 15)
        dout.writeByteArray(m_an2.toWire())
        exp = dout.toByteArray()
        dout = DnsOutput()
        ar.rrToWire(dout, null, false)
        assertTrue(Arrays.equals(exp, dout.toByteArray()))
    }
}
