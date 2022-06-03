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
import dorkbox.dns.dns.exceptions.TextParseException
import dorkbox.dns.dns.utils.Tokenizer
import junit.framework.Test
import junit.framework.TestCase
import junit.framework.TestSuite
import java.io.IOException
import java.util.*

class DSRecordTest : TestCase() {
    fun test_ctor_0arg() {
        val dr = DSRecord()
        try {
            // name isn't initialized yet!
            assertNull(dr.name)
            fail("Name should not be initialized!")
        } catch (ignored: Exception) {
        }
        assertEquals(0, dr.type)
        assertEquals(0, dr.dclass)
        assertEquals(0, dr.ttl)
        assertEquals(0, dr.algorithm)
        assertEquals(0, dr.digestID)
        assertNull(dr.digest)
        assertEquals(0, dr.footprint)
    }

    fun test_getObject() {
        val dr = DSRecord()
        val r = dr.`object`
        assertTrue(r is DSRecord)
    }

    class Test_Ctor_7arg : TestCase() {
        private lateinit var m_n: Name
        private var m_ttl: Long = 0
        private var m_footprint = 0
        private var m_algorithm = 0
        private var m_digestid = 0
        private lateinit var m_digest: ByteArray

        @Throws(TextParseException::class)
        override fun setUp() {
            m_n = fromString("The.Name.")
            m_ttl = 0xABCDL
            m_footprint = 0xEF01
            m_algorithm = 0x23
            m_digestid = 0x45
            m_digest = byteArrayOf(0x67.toByte(), 0x89.toByte(), 0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte())
        }

        @Throws(TextParseException::class)
        fun test_basic() {
            val dr = DSRecord(m_n, DnsClass.IN, m_ttl, m_footprint, m_algorithm, m_digestid, m_digest)
            assertEquals(m_n, dr.name)
            assertEquals(DnsClass.IN, dr.dclass)
            assertEquals(DnsRecordType.DS, dr.type)
            assertEquals(m_ttl, dr.ttl)
            assertEquals(m_footprint, dr.footprint)
            assertEquals(m_algorithm, dr.algorithm)
            assertEquals(m_digestid, dr.digestID)
            assertTrue(Arrays.equals(m_digest, dr.digest))
        }

        @Throws(TextParseException::class)
        fun test_toosmall_footprint() {
            try {
                DSRecord(m_n, DnsClass.IN, m_ttl, -1, m_algorithm, m_digestid, m_digest)
                fail("IllegalArgumentException not thrown")
            } catch (ignored: IllegalArgumentException) {
            }
        }

        @Throws(TextParseException::class)
        fun test_toobig_footprint() {
            try {
                DSRecord(m_n, DnsClass.IN, m_ttl, 0x10000, m_algorithm, m_digestid, m_digest)
                fail("IllegalArgumentException not thrown")
            } catch (ignored: IllegalArgumentException) {
            }
        }

        @Throws(TextParseException::class)
        fun test_toosmall_algorithm() {
            try {
                DSRecord(m_n, DnsClass.IN, m_ttl, m_footprint, -1, m_digestid, m_digest)
                fail("IllegalArgumentException not thrown")
            } catch (ignored: IllegalArgumentException) {
            }
        }

        @Throws(TextParseException::class)
        fun test_toobig_algorithm() {
            try {
                DSRecord(m_n, DnsClass.IN, m_ttl, m_footprint, 0x10000, m_digestid, m_digest)
                fail("IllegalArgumentException not thrown")
            } catch (ignored: IllegalArgumentException) {
            }
        }

        @Throws(TextParseException::class)
        fun test_toosmall_digestid() {
            try {
                DSRecord(m_n, DnsClass.IN, m_ttl, m_footprint, m_algorithm, -1, m_digest)
                fail("IllegalArgumentException not thrown")
            } catch (ignored: IllegalArgumentException) {
            }
        }

        @Throws(TextParseException::class)
        fun test_toobig_digestid() {
            try {
                DSRecord(m_n, DnsClass.IN, m_ttl, m_footprint, m_algorithm, 0x10000, m_digest)
                fail("IllegalArgumentException not thrown")
            } catch (ignored: IllegalArgumentException) {
            }
        }

        fun test_null_digest() {
            val dr = DSRecord(m_n, DnsClass.IN, m_ttl, m_footprint, m_algorithm, m_digestid, null)
            assertEquals(m_n, dr.name)
            assertEquals(DnsClass.IN, dr.dclass)
            assertEquals(DnsRecordType.DS, dr.type)
            assertEquals(m_ttl, dr.ttl)
            assertEquals(m_footprint, dr.footprint)
            assertEquals(m_algorithm, dr.algorithm)
            assertEquals(m_digestid, dr.digestID)
            assertNull(dr.digest)
        }
    }

    @Throws(IOException::class)
    fun test_rrFromWire() {
        val raw = byteArrayOf(
            0xAB.toByte(),
            0xCD.toByte(),
            0xEF.toByte(),
            0x01.toByte(),
            0x23.toByte(),
            0x45.toByte(),
            0x67.toByte(),
            0x89.toByte()
        )
        val `in` = DnsInput(raw)
        val dr = DSRecord()
        dr.rrFromWire(`in`)
        assertEquals(0xABCD, dr.footprint)
        assertEquals(0xEF, dr.algorithm)
        assertEquals(0x01, dr.digestID)
        assertTrue(Arrays.equals(byteArrayOf(0x23.toByte(), 0x45.toByte(), 0x67.toByte(), 0x89.toByte()), dr.digest))
    }

    @Throws(IOException::class)
    fun test_rdataFromString() {
        val raw = byteArrayOf(
            0xAB.toByte(),
            0xCD.toByte(),
            0xEF.toByte(),
            0x01.toByte(),
            0x23.toByte(),
            0x45.toByte(),
            0x67.toByte(),
            0x89.toByte()
        )
        val t = Tokenizer(0xABCD.toString() + " " + 0xEF + " " + 0x01 + " 23456789AB")
        val dr = DSRecord()
        dr.rdataFromString(t, null)
        assertEquals(0xABCD, dr.footprint)
        assertEquals(0xEF, dr.algorithm)
        assertEquals(0x01, dr.digestID)
        assertTrue(Arrays.equals(byteArrayOf(0x23.toByte(), 0x45.toByte(), 0x67.toByte(), 0x89.toByte(), 0xAB.toByte()), dr.digest))
    }

    @Throws(TextParseException::class)
    fun test_rrToString() {
        val exp = 0xABCD.toString() + " " + 0xEF + " " + 0x01 + " 23456789AB"
        val dr = DSRecord(
            fromString("The.Name."),
            DnsClass.IN,
            0x123,
            0xABCD,
            0xEF,
            0x01,
            byteArrayOf(0x23.toByte(), 0x45.toByte(), 0x67.toByte(), 0x89.toByte(), 0xAB.toByte())
        )
        val sb = StringBuilder()
        dr.rrToString(sb)
        assertEquals(exp, sb.toString())
    }

    @Throws(TextParseException::class)
    fun test_rrToWire() {
        val dr = DSRecord(
            fromString("The.Name."),
            DnsClass.IN,
            0x123,
            0xABCD,
            0xEF,
            0x01,
            byteArrayOf(0x23.toByte(), 0x45.toByte(), 0x67.toByte(), 0x89.toByte(), 0xAB.toByte())
        )
        val exp = byteArrayOf(
            0xAB.toByte(),
            0xCD.toByte(),
            0xEF.toByte(),
            0x01.toByte(),
            0x23.toByte(),
            0x45.toByte(),
            0x67.toByte(),
            0x89.toByte(),
            0xAB.toByte()
        )
        val out = DnsOutput()
        dr.rrToWire(out, null, true)
        assertTrue(Arrays.equals(exp, out.toByteArray()))
    }

    companion object {
        fun suite(): Test {
            val s = TestSuite()
            s.addTestSuite(Test_Ctor_7arg::class.java)
            s.addTestSuite(DSRecordTest::class.java)
            return s
        }
    }
}
