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
import dorkbox.dns.dns.Name.Companion.fromString
import dorkbox.dns.dns.constants.DnsClass
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.exceptions.TextParseException
import dorkbox.dns.dns.utils.Tokenizer
import junit.framework.TestCase
import java.io.IOException
import java.util.*

class URIRecordTest : TestCase() {
    fun test_ctor_0arg() {
        val r = URIRecord()
        try {
            // name isn't initialized yet!
            assertNull(r.name)
            fail("Name should not be initialized!")
        } catch (ignored: Exception) {
        }

        assertEquals(0, r.type)
        assertEquals(0, r.dclass)
        assertEquals(0, r.ttl)
        assertEquals(0, r.priority)
        assertEquals(0, r.weight)
        assertTrue("" == r.getTarget())
    }

    fun test_getObject() {
        val dr = URIRecord()
        val r = dr.`object`
        assertTrue(r is URIRecord)
    }

    @Throws(TextParseException::class)
    fun test_ctor_6arg() {
        val n = fromString("my.name.")
        val target = "http://foo"
        val r = URIRecord(n, DnsClass.IN, 0xABCDEL, 42, 69, target)

        assertEquals(n, r.name)
        assertEquals(DnsRecordType.URI, r.type)
        assertEquals(DnsClass.IN, r.dclass)
        assertEquals(0xABCDEL, r.ttl)
        assertEquals(42, r.priority)
        assertEquals(69, r.weight)
        assertEquals(target, r.getTarget())
    }

    @Throws(IOException::class)
    fun test_rdataFromString() {
        val t = Tokenizer(0xABCD.toString() + " " + 0xEF01 + " " + "\"http://foo:1234/bar?baz=bum\"")
        val r = URIRecord()
        r.rdataFromString(t, null)

        assertEquals(0xABCD, r.priority)
        assertEquals(0xEF01, r.weight)
        assertEquals("http://foo:1234/bar?baz=bum", r.getTarget())
    }

    @Throws(TextParseException::class)
    fun test_rdataToWire() {
        val n = fromString("my.name.")
        val target = "http://foo"
        val exp = byteArrayOf(
            0xbe.toByte(),
            0xef.toByte(),
            0xde.toByte(),
            0xad.toByte(),
            0x68.toByte(),
            0x74.toByte(),
            0x74.toByte(),
            0x70.toByte(),
            0x3a.toByte(),
            0x2f.toByte(),
            0x2f.toByte(),
            0x66.toByte(),
            0x6f.toByte(),
            0x6f.toByte()
        )

        val r = URIRecord(n, DnsClass.IN, 0xABCDEL, 0xbeef, 0xdead, target)
        val out = DnsOutput()
        r.rrToWire(out, null, true)
        assertTrue(Arrays.equals(exp, out.toByteArray()))
    }

    @Throws(IOException::class)
    fun test_rrFromWire() {
        val raw = byteArrayOf(
            0xbe.toByte(),
            0xef.toByte(),
            0xde.toByte(),
            0xad.toByte(),
            0x68.toByte(),
            0x74.toByte(),
            0x74.toByte(),
            0x70.toByte(),
            0x3a.toByte(),
            0x2f.toByte(),
            0x2f.toByte(),
            0x66.toByte(),
            0x6f.toByte(),
            0x6f.toByte()
        )

        val `in` = DnsInput(raw)
        val r = URIRecord()
        r.rrFromWire(`in`)
        assertEquals(0xBEEF, r.priority)
        assertEquals(0xDEAD, r.weight)
        assertEquals("http://foo", r.getTarget())
    }

    @Throws(TextParseException::class)
    fun test_toobig_priority() {
        try {
            URIRecord(fromString("the.name"), DnsClass.IN, 0x1234, 0x10000, 42, "http://foo")
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
    }

    @Throws(TextParseException::class)
    fun test_toosmall_priority() {
        try {
            URIRecord(fromString("the.name"), DnsClass.IN, 0x1234, -1, 42, "http://foo")
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
    }

    @Throws(TextParseException::class)
    fun test_toobig_weight() {
        try {
            URIRecord(fromString("the.name"), DnsClass.IN, 0x1234, 42, 0x10000, "http://foo")
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
    }

    @Throws(TextParseException::class)
    fun test_toosmall_weight() {
        try {
            URIRecord(fromString("the.name"), DnsClass.IN, 0x1234, 42, -1, "http://foo")
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
    }
}
