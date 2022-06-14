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

class AAAARecordTest : TestCase() {
    lateinit var m_an: Name
    lateinit var m_rn: Name
    lateinit var m_addr: InetAddress
    lateinit var m_addr_string: String
    lateinit var m_addr_bytes: ByteArray
    var m_ttl: Long = 0
    
    @Throws(TextParseException::class, UnknownHostException::class)
    override fun setUp() {
        m_an = fromString("My.Absolute.Name.")
        m_rn = fromString("My.Relative.Name")
        m_addr_string = "2001:db8:85a3:8d3:1319:8a2e:370:7334"
        m_addr = InetAddress.getByName(m_addr_string)
        m_addr_bytes = m_addr.getAddress()
        m_ttl = 0x13579
    }

    @Throws(UnknownHostException::class)
    fun test_ctor_0arg() {
        val ar = AAAARecord()
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
            assertNull(ar.address)
            fail("Name should not be initialized!")
        } catch (ignored: Exception) {
        }
    }

    fun test_getObject() {
        val ar = AAAARecord()
        val r = ar.dnsRecord
        assertTrue(r is AAAARecord)
    }

    fun test_ctor_4arg() {
        val ar = AAAARecord(m_an, DnsClass.IN, m_ttl, m_addr)
        assertEquals(m_an, ar.name)
        assertEquals(DnsRecordType.AAAA, ar.type)
        assertEquals(DnsClass.IN, ar.dclass)
        assertEquals(m_ttl, ar.ttl)
        assertEquals(m_addr, ar.address)

        // a relative name
        try {
            AAAARecord(m_rn, DnsClass.IN, m_ttl, m_addr)
            fail("RelativeNameException not thrown")
        } catch (ignored: RelativeNameException) {
        }

        // an IPv4 address
        try {
            AAAARecord(m_an, DnsClass.IN, m_ttl, InetAddress.getByName("192.168.0.1"))
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        } catch (e: UnknownHostException) {
            fail(e.message)
        }
    }

    @Throws(IOException::class)
    fun test_rrFromWire() {
        val di = DnsInput(m_addr_bytes)
        val ar = AAAARecord()
        ar.rrFromWire(di)
        assertEquals(m_addr, ar.address)
    }

    @Throws(IOException::class)
    fun test_rdataFromString() {
        var t = Tokenizer(m_addr_string)
        var ar = AAAARecord()
        ar.rdataFromString(t, null)
        assertEquals(m_addr, ar.address)

        // invalid address
        t = Tokenizer("193.160.232.1")
        ar = AAAARecord()
        try {
            ar.rdataFromString(t, null)
            fail("TextParseException not thrown")
         } catch (ignored: TextParseException) {
        }
    }

    fun test_rrToString() {
        val ar = AAAARecord(m_an, DnsClass.IN, m_ttl, m_addr)
        val sb = StringBuilder()
        ar.rrToString(sb)
        assertEquals(m_addr_string, sb.toString())
    }

    fun test_rrToWire() {
        val ar = AAAARecord(m_an, DnsClass.IN, m_ttl, m_addr)

        // canonical
        var dout = DnsOutput()
        ar.rrToWire(dout, null, true)
        assertTrue(Arrays.equals(m_addr_bytes, dout.toByteArray()))

        // case sensitive
        dout = DnsOutput()
        ar.rrToWire(dout, null, false)
        assertTrue(Arrays.equals(m_addr_bytes, dout.toByteArray()))
    }
}
