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
import dorkbox.dns.dns.utils.Options.set
import dorkbox.dns.dns.utils.Options.unset
import dorkbox.dns.dns.utils.Tokenizer
import junit.framework.Test
import junit.framework.TestCase
import junit.framework.TestSuite
import java.io.IOException
import java.net.UnknownHostException
import java.util.*

object SOARecordTest {
    private val m_random = Random()
    private fun randomU16(): Long {
        return m_random.nextLong() ushr 48
    }

    private fun randomU32(): Long {
        return m_random.nextLong() ushr 32
    }

    fun suite(): Test {
        val s = TestSuite()
        s.addTestSuite(Test_init::class.java)
        s.addTestSuite(Test_rrFromWire::class.java)
        s.addTestSuite(Test_rdataFromString::class.java)
        s.addTestSuite(Test_rrToString::class.java)
        s.addTestSuite(Test_rrToWire::class.java)
        return s
    }

    class Test_init : TestCase() {
        private var m_an: Name? = null
        private var m_rn: Name? = null
        private var m_host: Name? = null
        private var m_admin: Name? = null
        private var m_ttl: Long = 0
        private var m_serial: Long = 0
        private var m_refresh: Long = 0
        private var m_retry: Long = 0
        private var m_expire: Long = 0
        private var m_minimum: Long = 0

        @Throws(TextParseException::class, UnknownHostException::class)
        override fun setUp() {
            m_an = fromString("My.Absolute.Name.")
            m_rn = fromString("My.Relative.Name")
            m_host = fromString("My.Host.Name.")
            m_admin = fromString("My.Administrative.Name.")
            m_ttl = randomU16()
            m_serial = randomU32()
            m_refresh = randomU32()
            m_retry = randomU32()
            m_expire = randomU32()
            m_minimum = randomU32()
        }

        @Throws(UnknownHostException::class)
        fun test_0arg() {
            val ar = SOARecord()
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
                assertNull(ar.host)
                assertNull(ar.admin)
                fail("Name should not be initialized!")
            } catch (ignored: Exception) {
            }

            assertEquals(0, ar.serial)
            assertEquals(0, ar.refresh)
            assertEquals(0, ar.retry)
            assertEquals(0, ar.expire)
            assertEquals(0, ar.minimum)
        }

        fun test_getObject() {
            val ar = SOARecord()
            val r = ar.`object`
            assertTrue(r is SOARecord)
        }

        fun test_10arg() {
            val ar = SOARecord(m_an!!, DnsClass.IN, m_ttl, m_host!!, m_admin!!, m_serial, m_refresh, m_retry, m_expire, m_minimum)
            assertEquals(m_an, ar.name)
            assertEquals(DnsRecordType.SOA, ar.type)
            assertEquals(DnsClass.IN, ar.dclass)
            assertEquals(m_ttl, ar.ttl)
            assertEquals(m_host, ar.host)
            assertEquals(m_admin, ar.admin)
            assertEquals(m_serial, ar.serial)
            assertEquals(m_refresh, ar.refresh)
            assertEquals(m_retry, ar.retry)
            assertEquals(m_expire, ar.expire)
            assertEquals(m_minimum, ar.minimum)
        }

        fun test_10arg_relative_name() {
            try {
                SOARecord(m_rn!!, DnsClass.IN, m_ttl, m_host!!, m_admin!!, m_serial, m_refresh, m_retry, m_expire, m_minimum)
                fail("RelativeNameException not thrown")
            } catch (ignored: RelativeNameException) {
            }
        }

        fun test_10arg_relative_host() {
            try {
                SOARecord(m_an!!, DnsClass.IN, m_ttl, m_rn!!, m_admin!!, m_serial, m_refresh, m_retry, m_expire, m_minimum)
                fail("RelativeNameException not thrown")
            } catch (ignored: RelativeNameException) {
            }
        }

        fun test_10arg_relative_admin() {
            try {
                SOARecord(m_an!!, DnsClass.IN, m_ttl, m_host!!, m_rn!!, m_serial, m_refresh, m_retry, m_expire, m_minimum)
                fail("RelativeNameException not thrown")
            } catch (ignored: RelativeNameException) {
            }
        }

        fun test_10arg_negative_serial() {
            try {
                SOARecord(m_an!!, DnsClass.IN, m_ttl, m_host!!, m_admin!!, -1, m_refresh, m_retry, m_expire, m_minimum)
                fail("IllegalArgumentException not thrown")
            } catch (ignored: IllegalArgumentException) {
            }
        }

        fun test_10arg_toobig_serial() {
            try {
                SOARecord(m_an!!, DnsClass.IN, m_ttl, m_host!!, m_admin!!, 0x100000000L, m_refresh, m_retry, m_expire, m_minimum)
                fail("IllegalArgumentException not thrown")
            } catch (ignored: IllegalArgumentException) {
            }
        }

        fun test_10arg_negative_refresh() {
            try {
                SOARecord(m_an!!, DnsClass.IN, m_ttl, m_host!!, m_admin!!, m_serial, -1, m_retry, m_expire, m_minimum)
                fail("IllegalArgumentException not thrown")
            } catch (ignored: IllegalArgumentException) {
            }
        }

        fun test_10arg_toobig_refresh() {
            try {
                SOARecord(m_an!!, DnsClass.IN, m_ttl, m_host!!, m_admin!!, m_serial, 0x100000000L, m_retry, m_expire, m_minimum)
                fail("IllegalArgumentException not thrown")
            } catch (ignored: IllegalArgumentException) {
            }
        }

        fun test_10arg_negative_retry() {
            try {
                SOARecord(m_an!!, DnsClass.IN, m_ttl, m_host!!, m_admin!!, m_serial, m_refresh, -1, m_expire, m_minimum)
                fail("IllegalArgumentException not thrown")
            } catch (ignored: IllegalArgumentException) {
            }
        }

        fun test_10arg_toobig_retry() {
            try {
                SOARecord(m_an!!, DnsClass.IN, m_ttl, m_host!!, m_admin!!, m_serial, m_refresh, 0x100000000L, m_expire, m_minimum)
                fail("IllegalArgumentException not thrown")
            } catch (ignored: IllegalArgumentException) {
            }
        }

        fun test_10arg_negative_expire() {
            try {
                SOARecord(m_an!!, DnsClass.IN, m_ttl, m_host!!, m_admin!!, m_serial, m_refresh, m_retry, -1, m_minimum)
                fail("IllegalArgumentException not thrown")
            } catch (ignored: IllegalArgumentException) {
            }
        }

        fun test_10arg_toobig_expire() {
            try {
                SOARecord(m_an!!, DnsClass.IN, m_ttl, m_host!!, m_admin!!, m_serial, m_refresh, m_retry, 0x100000000L, m_minimum)
                fail("IllegalArgumentException not thrown")
            } catch (ignored: IllegalArgumentException) {
            }
        }

        fun test_10arg_negative_minimun() {
            try {
                SOARecord(m_an!!, DnsClass.IN, m_ttl, m_host!!, m_admin!!, m_serial, m_refresh, m_retry, m_expire, -1)
                fail("IllegalArgumentException not thrown")
            } catch (ignored: IllegalArgumentException) {
            }
        }

        fun test_10arg_toobig_minimum() {
            try {
                SOARecord(m_an!!, DnsClass.IN, m_ttl, m_host!!, m_admin!!, m_serial, m_refresh, m_retry, m_expire, 0x100000000L)
                fail("IllegalArgumentException not thrown")
            } catch (ignored: IllegalArgumentException) {
            }
        }
    }

    class Test_rrFromWire : TestCase() {
        private var m_host: Name? = null
        private var m_admin: Name? = null
        private var m_serial: Long = 0
        private var m_refresh: Long = 0
        private var m_retry: Long = 0
        private var m_expire: Long = 0
        private var m_minimum: Long = 0

        @Throws(IOException::class)
        fun test() {
            val raw = byteArrayOf(
                1,
                'm'.code.toByte(),
                1,
                'h'.code.toByte(),
                1,
                'n'.code.toByte(),
                0,  // host
                1,
                'm'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'n'.code.toByte(),
                0,
                0xAB.toByte(),
                0xCD.toByte(),
                0xEF.toByte(),
                0x12.toByte(),
                0xCD.toByte(),
                0xEF.toByte(),
                0x12.toByte(),
                0x34.toByte(),
                0xEF.toByte(),
                0x12.toByte(),
                0x34.toByte(),
                0x56.toByte(),
                0x12.toByte(),
                0x34.toByte(),
                0x56.toByte(),
                0x78.toByte(),
                0x34.toByte(),
                0x56.toByte(),
                0x78.toByte(),
                0x9A.toByte()
            )

            // minimum
            val di = DnsInput(raw)
            val ar = SOARecord()
            ar.rrFromWire(di)
            assertEquals(m_host, ar.host)
            assertEquals(m_admin, ar.admin)
            assertEquals(m_serial, ar.serial)
            assertEquals(m_refresh, ar.refresh)
            assertEquals(m_retry, ar.retry)
            assertEquals(m_expire, ar.expire)
            assertEquals(m_minimum, ar.minimum)
        }

        @Throws(TextParseException::class, UnknownHostException::class)
        override fun setUp() {
            m_host = fromString("M.h.N.")
            m_admin = fromString("M.a.n.")
            m_serial = 0xABCDEF12L
            m_refresh = 0xCDEF1234L
            m_retry = 0xEF123456L
            m_expire = 0x12345678L
            m_minimum = 0x3456789AL
        }
    }

    class Test_rdataFromString : TestCase() {
        private var m_host: Name? = null
        private var m_admin: Name? = null
        private var m_origin: Name? = null
        private var m_serial: Long = 0
        private var m_refresh: Long = 0
        private var m_retry: Long = 0
        private var m_expire: Long = 0
        private var m_minimum: Long = 0

        @Throws(IOException::class)
        fun test_valid() {
            val t = Tokenizer(
                "M.h " + m_admin + " " + m_serial + " " + m_refresh + " " + m_retry + " " + m_expire + " " + m_minimum
            )

            val ar = SOARecord()
            ar.rdataFromString(t, m_origin)
            assertEquals(m_host, ar.host)
            assertEquals(m_admin, ar.admin)
            assertEquals(m_serial, ar.serial)
            assertEquals(m_refresh, ar.refresh)
            assertEquals(m_retry, ar.retry)
            assertEquals(m_expire, ar.expire)
            assertEquals(m_minimum, ar.minimum)
        }

        @Throws(TextParseException::class, UnknownHostException::class)
        override fun setUp() {
            m_origin = fromString("O.")
            m_host = fromString("M.h", m_origin)
            m_admin = fromString("M.a.n.")
            m_serial = 0xABCDEF12L
            m_refresh = 0xCDEF1234L
            m_retry = 0xEF123456L
            m_expire = 0x12345678L
            m_minimum = 0x3456789AL
        }

        @Throws(IOException::class)
        fun test_relative_name() {
            val t = Tokenizer(
                "M.h " + m_admin + " " + m_serial + " " + m_refresh + " " + m_retry + " " + m_expire + " " + m_minimum
            )
            val ar = SOARecord()
            try {
                ar.rdataFromString(t, null)
                fail("RelativeNameException not thrown")
            } catch (ignored: RelativeNameException) {
            }
        }
    }

    class Test_rrToString : TestCase() {
        private lateinit var m_an: Name
        private lateinit var m_host: Name
        private lateinit var m_admin: Name
        private var m_ttl: Long = 0
        private var m_serial: Long = 0
        private var m_refresh: Long = 0
        private var m_retry: Long = 0
        private var m_expire: Long = 0
        private var m_minimum: Long = 0

        fun test_singleLine() {
            val ar = SOARecord(m_an, DnsClass.IN, m_ttl, m_host, m_admin, m_serial, m_refresh, m_retry, m_expire, m_minimum)
            val exp = m_host.toString() + " " + m_admin + " " + m_serial + " " + m_refresh + " " + m_retry + " " + m_expire + " " + m_minimum
            val sb = StringBuilder()
            ar.rrToString(sb)
            val out = sb.toString()
            assertEquals(exp, out)
        }

        @Throws(TextParseException::class)
        override fun setUp() {
            m_an = fromString("My.absolute.name.")
            m_ttl = 0x13A8
            m_host = fromString("M.h.N.")
            m_admin = fromString("M.a.n.")
            m_serial = 0xABCDEF12L
            m_refresh = 0xCDEF1234L
            m_retry = 0xEF123456L
            m_expire = 0x12345678L
            m_minimum = 0x3456789AL
        }

        fun test_multiLine() {
            val ar = SOARecord(m_an, DnsClass.IN, m_ttl, m_host, m_admin, m_serial, m_refresh, m_retry, m_expire, m_minimum)
            val re = "^.*\\(\\n" + "\\s*" + m_serial + "\\s*;\\s*serial\\n" +  // serial
                    "\\s*" + m_refresh + "\\s*;\\s*refresh\\n" +  // refresh
                    "\\s*" + m_retry + "\\s*;\\s*retry\\n" +  // retry
                    "\\s*" + m_expire + "\\s*;\\s*expire\\n" +  // expire
                    "\\s*" + m_minimum + "\\s*\\)\\s*;\\s*minimum$" // minimum

            set("multiline")
            val sb = StringBuilder()
            ar.rrToString(sb)
            val out = sb.toString()
            unset("multiline")
            assertTrue(out.matches(re.toRegex()))
        }
    }

    class Test_rrToWire : TestCase() {
        private lateinit var m_an: Name
        private lateinit var m_host: Name
        private lateinit var m_admin: Name
        private var m_ttl: Long = 0
        private var m_serial: Long = 0
        private var m_refresh: Long = 0
        private var m_retry: Long = 0
        private var m_expire: Long = 0
        private var m_minimum: Long = 0

        fun test_canonical() {
            val exp = byteArrayOf(
                1,
                'm'.code.toByte(),
                1,
                'h'.code.toByte(),
                1,
                'n'.code.toByte(),
                0,  // host
                1,
                'm'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'n'.code.toByte(),
                0,
                0xAB.toByte(),
                0xCD.toByte(),
                0xEF.toByte(),
                0x12.toByte(),
                0xCD.toByte(),
                0xEF.toByte(),
                0x12.toByte(),
                0x34.toByte(),
                0xEF.toByte(),
                0x12.toByte(),
                0x34.toByte(),
                0x56.toByte(),
                0x12.toByte(),
                0x34.toByte(),
                0x56.toByte(),
                0x78.toByte(),
                0x34.toByte(),
                0x56.toByte(),
                0x78.toByte(),
                0x9A.toByte()
            ) // minimum

            val ar = SOARecord(m_an, DnsClass.IN, m_ttl, m_host, m_admin, m_serial, m_refresh, m_retry, m_expire, m_minimum)
            val o = DnsOutput()
            ar.rrToWire(o, null, true)
            assertTrue(Arrays.equals(exp, o.toByteArray()))
        }

        @Throws(TextParseException::class)
        override fun setUp() {
            m_an = fromString("My.Abs.Name.")
            m_ttl = 0x13A8
            m_host = fromString("M.h.N.")
            m_admin = fromString("M.a.n.")
            m_serial = 0xABCDEF12L
            m_refresh = 0xCDEF1234L
            m_retry = 0xEF123456L
            m_expire = 0x12345678L
            m_minimum = 0x3456789AL
        }

        fun test_case_sensitive() {
            val exp = byteArrayOf(
                1,
                'M'.code.toByte(),
                1,
                'h'.code.toByte(),
                1,
                'N'.code.toByte(),
                0,  // host
                1,
                'M'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'n'.code.toByte(),
                0,
                0xAB.toByte(),
                0xCD.toByte(),
                0xEF.toByte(),
                0x12.toByte(),
                0xCD.toByte(),
                0xEF.toByte(),
                0x12.toByte(),
                0x34.toByte(),
                0xEF.toByte(),
                0x12.toByte(),
                0x34.toByte(),
                0x56.toByte(),
                0x12.toByte(),
                0x34.toByte(),
                0x56.toByte(),
                0x78.toByte(),
                0x34.toByte(),
                0x56.toByte(),
                0x78.toByte(),
                0x9A.toByte()
            ) // minimum

            val ar = SOARecord(m_an, DnsClass.IN, m_ttl, m_host, m_admin, m_serial, m_refresh, m_retry, m_expire, m_minimum)
            val o = DnsOutput()
            ar.rrToWire(o, null, false)
            assertTrue(Arrays.equals(exp, o.toByteArray()))
        }
    }
}
