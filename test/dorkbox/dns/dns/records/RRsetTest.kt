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

import dorkbox.dns.dns.Name
import dorkbox.dns.dns.Name.Companion.fromString
import dorkbox.dns.dns.constants.DnsClass
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.exceptions.TextParseException
import junit.framework.TestCase
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.*

class RRsetTest : TestCase() {
    lateinit var m_rs: RRset
    lateinit var m_name: Name
    lateinit var m_name2: Name
    var m_ttl: Long = 0
    lateinit var m_a1: ARecord
    lateinit var m_a2: ARecord
    lateinit var m_s1: RRSIGRecord
    lateinit var m_s2: RRSIGRecord

    @Throws(TextParseException::class, UnknownHostException::class)
    public override fun setUp() {
        m_rs = RRset()
        m_name = fromString("this.is.a.test.")
        m_name2 = fromString("this.is.another.test.")
        m_ttl = 0xABCDL
        m_a1 = ARecord(m_name, DnsClass.IN, m_ttl, InetAddress.getByName("192.169.232.11"))
        m_a2 = ARecord(m_name, DnsClass.IN, m_ttl + 1, InetAddress.getByName("192.169.232.12"))
        m_s1 = RRSIGRecord(
            m_name, DnsClass.IN, m_ttl, DnsRecordType.A, 0xF, 0xABCDEL, Date(), Date(), 0xA, m_name, ByteArray(0)
        )
        m_s2 = RRSIGRecord(
            m_name, DnsClass.IN, m_ttl, DnsRecordType.A, 0xF, 0xABCDEL, Date(), Date(), 0xA, m_name2, ByteArray(0)
        )
    }

    fun test_ctor_0arg() {
        assertEquals(0, m_rs.size())
        try {
            m_rs.dClass
            fail("IllegalStateException not thrown")
        } catch (ignored: IllegalStateException) {
        }
        try {
            m_rs.type
            fail("IllegalStateException not thrown")
        } catch (ignored: IllegalStateException) {
        }
        try {
            m_rs.TTL
            fail("IllegalStateException not thrown")
        } catch (ignored: IllegalStateException) {
        }
        try {
            m_rs.name
            fail("IllegalStateException not thrown")
        } catch (ignored: IllegalStateException) {
        }
        try {
            m_rs.first()
            fail("IllegalStateException not thrown")
        } catch (ignored: IllegalStateException) {
        }
        
        assertEquals("{empty}", m_rs.toString())
        
        var itr = m_rs.rrs()
        assertNotNull(itr)
        assertFalse(itr.hasNext())
        
        itr = m_rs.sigs()
        assertNotNull(itr)
        assertFalse(itr.hasNext())
    }

    @Throws(TextParseException::class, UnknownHostException::class)
    fun test_basics() {
        m_rs.addRR(m_a1)
        assertEquals(1, m_rs.size())
        assertEquals(DnsClass.IN, m_rs.dClass)
        assertEquals(m_a1, m_rs.first())
        assertEquals(m_name, m_rs.name)
        assertEquals(m_ttl, m_rs.TTL)
        assertEquals(DnsRecordType.A, m_rs.type)

        // add it again, and make sure nothing changed
        m_rs.addRR(m_a1)
        assertEquals(1, m_rs.size())
        assertEquals(DnsClass.IN, m_rs.dClass)
        assertEquals(m_a1, m_rs.first())
        assertEquals(m_name, m_rs.name)
        assertEquals(m_ttl, m_rs.TTL)
        assertEquals(DnsRecordType.A, m_rs.type)
        
        m_rs.addRR(m_a2)
        assertEquals(2, m_rs.size())
        assertEquals(DnsClass.IN, m_rs.dClass)
        
        val r = m_rs.first()
        assertEquals(m_a1, r)
        assertEquals(m_name, m_rs.name)
        assertEquals(m_ttl, m_rs.TTL)
        assertEquals(DnsRecordType.A, m_rs.type)
        
        var itr = m_rs.rrs()
        assertEquals(m_a1, itr.next())
        assertEquals(m_a2, itr.next())

        // make sure that it rotates
        itr = m_rs.rrs()
        
        assertEquals(m_a2, itr.next())
        assertEquals(m_a1, itr.next())
        
        itr = m_rs.rrs()
        
        assertEquals(m_a1, itr.next())
        assertEquals(m_a2, itr.next())
        
        m_rs.deleteRR(m_a1)
        
        assertEquals(1, m_rs.size())
        assertEquals(DnsClass.IN, m_rs.dClass)
        assertEquals(m_a2, m_rs.first())
        assertEquals(m_name, m_rs.name)
        assertEquals(m_ttl, m_rs.TTL)
        assertEquals(DnsRecordType.A, m_rs.type)

        // the signature records
        m_rs.addRR(m_s1)
        assertEquals(1, m_rs.size())
        
        itr = m_rs.sigs()
        
        assertEquals(m_s1, itr.next())
        assertFalse(itr.hasNext())
        
        m_rs.addRR(m_s1)
        itr = m_rs.sigs()
        
        assertEquals(m_s1, itr.next())
        assertFalse(itr.hasNext())
        
        m_rs.addRR(m_s2)
        itr = m_rs.sigs()
        
        assertEquals(m_s1, itr.next())
        assertEquals(m_s2, itr.next())
        assertFalse(itr.hasNext())
        
        m_rs.deleteRR(m_s1)
        itr = m_rs.sigs()
        
        assertEquals(m_s2, itr.next())
        assertFalse(itr.hasNext())


        // clear it all
        m_rs.clear()
        assertEquals(0, m_rs.size())
        assertFalse(m_rs.rrs().hasNext())
        assertFalse(m_rs.sigs().hasNext())
    }

    fun test_ctor_1arg() {
        m_rs.addRR(m_a1)
        m_rs.addRR(m_a2)
        m_rs.addRR(m_s1)
        m_rs.addRR(m_s2)
        val rs2 = RRset(m_rs)
        assertEquals(2, rs2.size())
        assertEquals(m_a1, rs2.first())
        
        var itr = rs2.rrs()
        assertEquals(m_a1, itr.next())
        assertEquals(m_a2, itr.next())
        assertFalse(itr.hasNext())
        
        itr = rs2.sigs()
        assertTrue(itr.hasNext())
        assertEquals(m_s1, itr.next())
        assertTrue(itr.hasNext())
        assertEquals(m_s2, itr.next())
        assertFalse(itr.hasNext())
    }

    fun test_toString() {
        m_rs.addRR(m_a1)
        m_rs.addRR(m_a2)
        m_rs.addRR(m_s1)
        m_rs.addRR(m_s2)
        
        val out = m_rs.toString()
        assertTrue(out.indexOf(m_name.toString()) != -1)
        assertTrue(out.indexOf(" IN A ") != -1)
        assertTrue(out.indexOf("[192.169.232.11]") != -1)
        assertTrue(out.indexOf("[192.169.232.12]") != -1)
    }

    @Throws(TextParseException::class)
    fun test_addRR_invalidType() {
        m_rs.addRR(m_a1)
        val c = CNAMERecord(m_name, DnsClass.IN, m_ttl, fromString("an.alias."))
        try {
            m_rs.addRR(c)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
    }

    @Throws(TextParseException::class, UnknownHostException::class)
    fun test_addRR_invalidName() {
        m_rs.addRR(m_a1)
        m_a2 = ARecord(m_name2, DnsClass.IN, m_ttl, InetAddress.getByName("192.169.232.11"))
        try {
            m_rs.addRR(m_a2)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
    }

    @Throws(TextParseException::class, UnknownHostException::class)
    fun test_addRR_invalidDClass() {
        m_rs.addRR(m_a1)
        m_a2 = ARecord(m_name, DnsClass.CHAOS, m_ttl, InetAddress.getByName("192.169.232.11"))
        try {
            m_rs.addRR(m_a2)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
    }

    fun test_TTLcalculation() {
        m_rs.addRR(m_a2)
        assertEquals(m_a2.ttl, m_rs.TTL)
        m_rs.addRR(m_a1)
        assertEquals(m_a1.ttl, m_rs.TTL)

        val itr = m_rs.rrs()
        while (itr.hasNext()) {
            val r = itr.next() as DnsRecord
            assertEquals(m_a1.ttl, r.ttl)
        }
    }

    fun test_Record_placement() {
        m_rs.addRR(m_a1)
        m_rs.addRR(m_s1)
        m_rs.addRR(m_a2)
        var itr = m_rs.rrs()
        assertTrue(itr.hasNext())
        assertEquals(m_a1, itr.next())
        assertTrue(itr.hasNext())
        assertEquals(m_a2, itr.next())
        assertFalse(itr.hasNext())

        itr = m_rs.sigs()
        assertTrue(itr.hasNext())
        assertEquals(m_s1, itr.next())
        assertFalse(itr.hasNext())
    }

    fun test_noncycling_iterator() {
        m_rs.addRR(m_a1)
        m_rs.addRR(m_a2)
        var itr = m_rs.rrs(false)
        assertTrue(itr.hasNext())
        assertEquals(m_a1, itr.next())
        assertTrue(itr.hasNext())
        assertEquals(m_a2, itr.next())

        itr = m_rs.rrs(false)
        assertTrue(itr.hasNext())
        assertEquals(m_a1, itr.next())
        assertTrue(itr.hasNext())
        assertEquals(m_a2, itr.next())
    }
}
