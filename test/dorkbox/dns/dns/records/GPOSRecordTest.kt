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
import dorkbox.dns.dns.exceptions.WireParseException
import dorkbox.dns.dns.utils.Tokenizer
import junit.framework.Test
import junit.framework.TestCase
import junit.framework.TestSuite
import java.io.IOException

class GPOSRecordTest : TestCase() {
    fun test_ctor_0arg() {
        val gr = GPOSRecord()
        try {
            // name isn't initialized yet!
            assertNull(gr.name)
            fail("Name should not be initialized!")
        } catch (ignored: Exception) {
        }
        assertEquals(0, gr.type)
        assertEquals(0, gr.dclass)
        assertEquals(0, gr.ttl)
    }

    fun test_getObject() {
        val gr = GPOSRecord()
        val r = gr.`object`
        assertTrue(r is GPOSRecord)
    }

    class Test_Ctor_6arg_doubles : TestCase() {
        private var m_n: Name? = null
        private var m_ttl: Long = 0
        private var m_lat = 0.0
        private var m_long = 0.0
        private var m_alt = 0.0
        @Throws(TextParseException::class)
        override fun setUp() {
            m_n = fromString("The.Name.")
            m_ttl = 0xABCDL
            m_lat = -10.43
            m_long = 76.12
            m_alt = 100.101
        }

        @Throws(TextParseException::class)
        fun test_basic() {
            val gr = GPOSRecord(m_n, DnsClass.IN, m_ttl, m_long, m_lat, m_alt)
            assertEquals(m_n, gr.name)
            assertEquals(DnsClass.IN, gr.dclass)
            assertEquals(DnsRecordType.GPOS, gr.type)
            assertEquals(m_ttl, gr.ttl)
            assertEquals(m_long, gr.getLongitude())
            assertEquals(m_lat, gr.getLatitude())
            assertEquals(m_alt, gr.getAltitude())
            assertEquals(java.lang.Double.toString(m_long), gr.longitudeString)
            assertEquals(java.lang.Double.toString(m_lat), gr.latitudeString)
            assertEquals(java.lang.Double.toString(m_alt), gr.altitudeString)
        }

        @Throws(TextParseException::class)
        fun test_toosmall_longitude() {
            try {
                GPOSRecord(m_n, DnsClass.IN, m_ttl, -90.001, m_lat, m_alt)
                fail("IllegalArgumentException not thrown")
            } catch (e: IllegalArgumentException) {
            }
        }

        @Throws(TextParseException::class)
        fun test_toobig_longitude() {
            try {
                GPOSRecord(m_n, DnsClass.IN, m_ttl, 90.001, m_lat, m_alt)
                fail("IllegalArgumentException not thrown")
            } catch (e: IllegalArgumentException) {
            }
        }

        @Throws(TextParseException::class)
        fun test_toosmall_latitude() {
            try {
                GPOSRecord(m_n, DnsClass.IN, m_ttl, m_long, -180.001, m_alt)
                fail("IllegalArgumentException not thrown")
            } catch (e: IllegalArgumentException) {
            }
        }

        @Throws(TextParseException::class)
        fun test_toobig_latitude() {
            try {
                GPOSRecord(m_n, DnsClass.IN, m_ttl, m_long, 180.001, m_alt)
                fail("IllegalArgumentException not thrown")
            } catch (e: IllegalArgumentException) {
            }
        }

        fun test_invalid_string() {
            try {
                GPOSRecord(m_n, DnsClass.IN, m_ttl, java.lang.Double.toString(m_long), "120.\\00ABC", java.lang.Double.toString(m_alt))
                fail("IllegalArgumentException not thrown")
            } catch (e: IllegalArgumentException) {
            }
        }
    }

    class Test_Ctor_6arg_Strings : TestCase() {
        private var m_n: Name? = null
        private var m_ttl: Long = 0
        private var m_lat = 0.0
        private var m_long = 0.0
        private var m_alt = 0.0
        @Throws(TextParseException::class)
        fun test_basic() {
            val gr = GPOSRecord(
                m_n,
                DnsClass.IN,
                m_ttl,
                java.lang.Double.toString(m_long),
                java.lang.Double.toString(m_lat),
                java.lang.Double.toString(m_alt)
            )
            assertEquals(m_n, gr.name)
            assertEquals(DnsClass.IN, gr.dclass)
            assertEquals(DnsRecordType.GPOS, gr.type)
            assertEquals(m_ttl, gr.ttl)
            assertEquals(m_long, gr.getLongitude())
            assertEquals(m_lat, gr.getLatitude())
            assertEquals(m_alt, gr.getAltitude())
            assertEquals(java.lang.Double.toString(m_long), gr.longitudeString)
            assertEquals(java.lang.Double.toString(m_lat), gr.latitudeString)
            assertEquals(java.lang.Double.toString(m_alt), gr.altitudeString)
        }

        @Throws(TextParseException::class)
        fun test_toosmall_longitude() {
            try {
                GPOSRecord(m_n, DnsClass.IN, m_ttl, "-90.001", java.lang.Double.toString(m_lat), java.lang.Double.toString(m_alt))
                fail("IllegalArgumentException not thrown")
            } catch (e: IllegalArgumentException) {
            }
        }

        @Throws(TextParseException::class)
        override fun setUp() {
            m_n = fromString("The.Name.")
            m_ttl = 0xABCDL
            m_lat = -10.43
            m_long = 76.12
            m_alt = 100.101
        }

        @Throws(TextParseException::class)
        fun test_toobig_longitude() {
            try {
                GPOSRecord(m_n, DnsClass.IN, m_ttl, "90.001", java.lang.Double.toString(m_lat), java.lang.Double.toString(m_alt))
                fail("IllegalArgumentException not thrown")
            } catch (e: IllegalArgumentException) {
            }
        }

        @Throws(TextParseException::class)
        fun test_toosmall_latitude() {
            try {
                GPOSRecord(m_n, DnsClass.IN, m_ttl, java.lang.Double.toString(m_long), "-180.001", java.lang.Double.toString(m_alt))
                fail("IllegalArgumentException not thrown")
            } catch (e: IllegalArgumentException) {
            }
        }

        @Throws(TextParseException::class)
        fun test_toobig_latitude() {
            try {
                GPOSRecord(m_n, DnsClass.IN, m_ttl, java.lang.Double.toString(m_long), "180.001", java.lang.Double.toString(m_alt))
                fail("IllegalArgumentException not thrown")
            } catch (e: IllegalArgumentException) {
            }
        }
    }

    class Test_rrFromWire : TestCase() {
        @Throws(IOException::class)
        fun test_basic() {
            val raw = byteArrayOf(
                5,
                '-'.code.toByte(),
                '8'.code.toByte(),
                '.'.code.toByte(),
                '1'.code.toByte(),
                '2'.code.toByte(),
                6,
                '1'.code.toByte(),
                '2'.code.toByte(),
                '3'.code.toByte(),
                '.'.code.toByte(),
                '0'.code.toByte(),
                '7'.code.toByte(),
                3,
                '0'.code.toByte(),
                '.'.code.toByte(),
                '0'.code.toByte()
            )
            val `in` = DnsInput(raw)
            val gr = GPOSRecord()
            gr.rrFromWire(`in`)
            assertEquals(-8.12, gr.getLongitude())
            assertEquals(123.07, gr.getLatitude())
            assertEquals(0.0, gr.getAltitude())
        }

        @Throws(IOException::class)
        fun test_longitude_toosmall() {
            val raw = byteArrayOf(
                5,
                '-'.code.toByte(),
                '9'.code.toByte(),
                '5'.code.toByte(),
                '.'.code.toByte(),
                '0'.code.toByte(),
                6,
                '1'.code.toByte(),
                '2'.code.toByte(),
                '3'.code.toByte(),
                '.'.code.toByte(),
                '0'.code.toByte(),
                '7'.code.toByte(),
                3,
                '0'.code.toByte(),
                '.'.code.toByte(),
                '0'.code.toByte()
            )
            val `in` = DnsInput(raw)
            val gr = GPOSRecord()
            try {
                gr.rrFromWire(`in`)
                fail("WireParseException not thrown")
            } catch (e: WireParseException) {
            }
        }

        @Throws(IOException::class)
        fun test_longitude_toobig() {
            val raw = byteArrayOf(
                5,
                '1'.code.toByte(),
                '8'.code.toByte(),
                '5'.code.toByte(),
                '.'.code.toByte(),
                '0'.code.toByte(),
                6,
                '1'.code.toByte(),
                '2'.code.toByte(),
                '3'.code.toByte(),
                '.'.code.toByte(),
                '0'.code.toByte(),
                '7'.code.toByte(),
                3,
                '0'.code.toByte(),
                '.'.code.toByte(),
                '0'.code.toByte()
            )
            val `in` = DnsInput(raw)
            val gr = GPOSRecord()
            try {
                gr.rrFromWire(`in`)
                fail("WireParseException not thrown")
            } catch (e: WireParseException) {
            }
        }

        @Throws(IOException::class)
        fun test_latitude_toosmall() {
            val raw = byteArrayOf(
                5,
                '-'.code.toByte(),
                '8'.code.toByte(),
                '5'.code.toByte(),
                '.'.code.toByte(),
                '0'.code.toByte(),
                6,
                '-'.code.toByte(),
                '1'.code.toByte(),
                '9'.code.toByte(),
                '0'.code.toByte(),
                '.'.code.toByte(),
                '0'.code.toByte(),
                3,
                '0'.code.toByte(),
                '.'.code.toByte(),
                '0'.code.toByte()
            )
            val `in` = DnsInput(raw)
            val gr = GPOSRecord()
            try {
                gr.rrFromWire(`in`)
                fail("WireParseException not thrown")
            } catch (e: WireParseException) {
            }
        }

        @Throws(IOException::class)
        fun test_latitude_toobig() {
            val raw = byteArrayOf(
                5,
                '-'.code.toByte(),
                '8'.code.toByte(),
                '5'.code.toByte(),
                '.'.code.toByte(),
                '0'.code.toByte(),
                6,
                '2'.code.toByte(),
                '1'.code.toByte(),
                '9'.code.toByte(),
                '0'.code.toByte(),
                '.'.code.toByte(),
                '0'.code.toByte(),
                3,
                '0'.code.toByte(),
                '.'.code.toByte(),
                '0'.code.toByte()
            )
            val `in` = DnsInput(raw)
            val gr = GPOSRecord()
            try {
                gr.rrFromWire(`in`)
                fail("WireParseException not thrown")
            } catch (e: WireParseException) {
            }
        }
    }

    class Test_rdataFromString : TestCase() {
        @Throws(IOException::class)
        fun test_basic() {
            val t = Tokenizer("10.45 171.121212 1010787")
            val gr = GPOSRecord()
            gr.rdataFromString(t, null)
            assertEquals(10.45, gr.getLongitude())
            assertEquals(171.121212, gr.getLatitude())
            assertEquals(1010787.0, gr.getAltitude())
        }

        @Throws(IOException::class)
        fun test_longitude_toosmall() {
            val t = Tokenizer("-100.390 171.121212 1010787")
            val gr = GPOSRecord()
            try {
                gr.rdataFromString(t, null)
                fail("IOException not thrown")
            } catch (e: IOException) {
            }
        }

        @Throws(IOException::class)
        fun test_longitude_toobig() {
            val t = Tokenizer("90.00001 171.121212 1010787")
            val gr = GPOSRecord()
            try {
                gr.rdataFromString(t, null)
                fail("IOException not thrown")
            } catch (e: IOException) {
            }
        }

        @Throws(IOException::class)
        fun test_latitude_toosmall() {
            val t = Tokenizer("0.0 -180.01 1010787")
            val gr = GPOSRecord()
            try {
                gr.rdataFromString(t, null)
                fail("IOException not thrown")
            } catch (e: IOException) {
            }
        }

        @Throws(IOException::class)
        fun test_latitude_toobig() {
            val t = Tokenizer("0.0 180.01 1010787")
            val gr = GPOSRecord()
            try {
                gr.rdataFromString(t, null)
                fail("IOException not thrown")
            } catch (e: IOException) {
            }
        }

        @Throws(IOException::class)
        fun test_invalid_string() {
            val t = Tokenizer("1.0 2.0 \\435")
            try {
                val gr = GPOSRecord()
                gr.rdataFromString(t, null)
            } catch (e: TextParseException) {
            }
        }
    }

    @Throws(TextParseException::class)
    fun test_rrToString() {
        val exp = "\"10.45\" \"171.121212\" \"1010787.0\""
        val gr = GPOSRecord(fromString("The.Name."), DnsClass.IN, 0x123, 10.45, 171.121212, 1010787.0)
        val sb = StringBuilder()
        gr.rrToString(sb)
        assertEquals(exp, sb.toString())
    }

    @Throws(TextParseException::class)
    fun test_rrToWire() {
        val gr = GPOSRecord(fromString("The.Name."), DnsClass.IN, 0x123, -10.45, 120.0, 111.0)
        val exp = byteArrayOf(
            6,
            '-'.code.toByte(),
            '1'.code.toByte(),
            '0'.code.toByte(),
            '.'.code.toByte(),
            '4'.code.toByte(),
            '5'.code.toByte(),
            5,
            '1'.code.toByte(),
            '2'.code.toByte(),
            '0'.code.toByte(),
            '.'.code.toByte(),
            '0'.code.toByte(),
            5,
            '1'.code.toByte(),
            '1'.code.toByte(),
            '1'.code.toByte(),
            '.'.code.toByte(),
            '0'.code.toByte()
        )
        val out = DnsOutput()
        gr.rrToWire(out, null, true)
        val bar = out.toByteArray()
        assertEquals(exp.size, bar.size)
        for (i in exp.indices) {
            assertEquals("i=$i", exp[i], bar[i])
        }
    }

    companion object {
        fun suite(): Test {
            val s = TestSuite()
            s.addTestSuite(Test_Ctor_6arg_doubles::class.java)
            s.addTestSuite(Test_Ctor_6arg_Strings::class.java)
            s.addTestSuite(Test_rrFromWire::class.java)
            s.addTestSuite(Test_rdataFromString::class.java)
            s.addTestSuite(GPOSRecordTest::class.java)
            return s
        }
    }
}
