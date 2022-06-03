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

import dorkbox.dns.dns.Name.Companion.fromString
import dorkbox.dns.dns.constants.DnsClass
import dorkbox.dns.dns.constants.DnsOpCode
import dorkbox.dns.dns.constants.DnsSection
import dorkbox.dns.dns.constants.Flags
import dorkbox.dns.dns.exceptions.TextParseException
import dorkbox.dns.dns.records.DnsMessage.Companion.newQuery
import junit.framework.Test
import junit.framework.TestCase
import junit.framework.TestSuite
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.*

object MessageTest {
    fun suite(): Test {
        val s = TestSuite()
        s.addTestSuite(Test_init::class.java)
        return s
    }

    class Test_init : TestCase() {
        fun test_0arg() {
            val m = DnsMessage()
            assertTrue(Arrays.equals(arrayOfNulls<DnsRecord>(0), m.getSectionArray(0)))
            assertTrue(Arrays.equals(arrayOfNulls<DnsRecord>(0), m.getSectionArray(1)))
            assertTrue(Arrays.equals(arrayOfNulls<DnsRecord>(0), m.getSectionArray(2)))
            assertTrue(Arrays.equals(arrayOfNulls<DnsRecord>(0), m.getSectionArray(3)))
            try {
                m.getSectionArray(4)
                fail("IndexOutOfBoundsException not thrown")
            } catch (ignored: IndexOutOfBoundsException) {
            }
            val h = m.header
            assertEquals(0, h.getCount(0))
            assertEquals(0, h.getCount(1))
            assertEquals(0, h.getCount(2))
            assertEquals(0, h.getCount(3))
        }

        fun test_1arg() {
            val m = DnsMessage(10)
            assertEquals(
                Header(10).toString(), m.header.toString()
            )
            assertTrue(Arrays.equals(arrayOfNulls<DnsRecord>(0), m.getSectionArray(0)))
            assertTrue(Arrays.equals(arrayOfNulls<DnsRecord>(0), m.getSectionArray(1)))
            assertTrue(Arrays.equals(arrayOfNulls<DnsRecord>(0), m.getSectionArray(2)))
            assertTrue(Arrays.equals(arrayOfNulls<DnsRecord>(0), m.getSectionArray(3)))
            try {
                m.getSectionArray(4)
                fail("IndexOutOfBoundsException not thrown")
            } catch (ignored: IndexOutOfBoundsException) {
            }
            val h = m.header
            assertEquals(0, h.getCount(0))
            assertEquals(0, h.getCount(1))
            assertEquals(0, h.getCount(2))
            assertEquals(0, h.getCount(3))
        }

        @Throws(TextParseException::class, UnknownHostException::class)
        fun test_newQuery() {
            val n = fromString("The.Name.")
            val ar = ARecord(n, DnsClass.IN, 1, InetAddress.getByName("192.168.101.110"))
            val m = newQuery(ar)
            assertTrue(Arrays.equals(arrayOf<DnsRecord>(ar), m.getSectionArray(DnsSection.QUESTION)))
            assertTrue(Arrays.equals(arrayOfNulls<DnsRecord>(0), m.getSectionArray(DnsSection.ANSWER)))
            assertTrue(Arrays.equals(arrayOfNulls<DnsRecord>(0), m.getSectionArray(DnsSection.AUTHORITY)))
            assertTrue(Arrays.equals(arrayOfNulls<DnsRecord>(0), m.getSectionArray(DnsSection.ADDITIONAL)))
            val h = m.header
            assertEquals(1, h.getCount(DnsSection.QUESTION))
            assertEquals(0, h.getCount(DnsSection.ANSWER))
            assertEquals(0, h.getCount(DnsSection.AUTHORITY))
            assertEquals(0, h.getCount(DnsSection.ADDITIONAL))
            assertEquals(DnsOpCode.QUERY, h.opcode)
            assertEquals(true, h.getFlag(Flags.RD))
        }
    }
}
