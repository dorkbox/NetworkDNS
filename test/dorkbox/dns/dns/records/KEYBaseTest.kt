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
import dorkbox.dns.dns.utils.Options.set
import dorkbox.dns.dns.utils.Options.unset
import dorkbox.dns.dns.utils.Tokenizer
import dorkbox.os.OS.LINE_SEPARATOR
import junit.framework.TestCase
import java.io.IOException
import java.util.*

class KEYBaseTest : TestCase() {
    private class TestClass : KEYBase {
        constructor() {}
        constructor(name: Name?, type: Int, dclass: Int, ttl: Long, flags: Int, proto: Int, alg: Int, key: ByteArray?) : super(
            name!!, type, dclass, ttl, flags, proto, alg, key
        ) {
        }

        override val `object`: DnsRecord
            get() = this

        @Throws(IOException::class)
        override fun rdataFromString(st: Tokenizer, origin: Name?) {
        }
    }

    @Throws(TextParseException::class)
    fun test_ctor() {
        var tc = TestClass()
        assertEquals(0, tc.flags)
        assertEquals(0, tc.protocol)
        assertEquals(0, tc.algorithm)
        assertNull(tc.key)
        val n = fromString("my.name.")
        val key = byteArrayOf(0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF)
        tc = TestClass(n, DnsRecordType.KEY, DnsClass.IN, 100L, 0xFF, 0xF, 0xE, key)
        assertSame(n, tc.name)
        assertEquals(DnsRecordType.KEY, tc.type)
        assertEquals(DnsClass.IN, tc.dclass)
        assertEquals(100L, tc.ttl)
        assertEquals(0xFF, tc.flags)
        assertEquals(0xF, tc.protocol)
        assertEquals(0xE, tc.algorithm)
        assertTrue(Arrays.equals(key, tc.key))
    }

    @Throws(IOException::class)
    fun test_rrFromWire() {
        var raw = byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte(), 0x19.toByte(), 1, 2, 3, 4, 5)
        var `in` = DnsInput(raw)
        var tc = TestClass()
        tc.rrFromWire(`in`)
        assertEquals(0xABCD, tc.flags)
        assertEquals(0xEF, tc.protocol)
        assertEquals(0x19, tc.algorithm)
        assertTrue(Arrays.equals(byteArrayOf(1, 2, 3, 4, 5), tc.key))
        raw = byteArrayOf(0xBA.toByte(), 0xDA.toByte(), 0xFF.toByte(), 0x28.toByte())
        `in` = DnsInput(raw)
        tc = TestClass()
        tc.rrFromWire(`in`)
        assertEquals(0xBADA, tc.flags)
        assertEquals(0xFF, tc.protocol)
        assertEquals(0x28, tc.algorithm)
        assertNull(tc.key)
    }

    @Throws(IOException::class, TextParseException::class)
    fun test_rrToString() {
        val n = fromString("my.name.")
        val key = byteArrayOf(0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF)
        var tc = TestClass(n, DnsRecordType.KEY, DnsClass.IN, 100L, 0xFF, 0xF, 0xE, null)
        var sb = StringBuilder()
        tc.rrToString(sb)
        var out = sb.toString()
        assertEquals("255 15 14", out)
        tc = TestClass(n, DnsRecordType.KEY, DnsClass.IN, 100L, 0xFF, 0xF, 0xE, key)
        sb = StringBuilder()
        tc.rrToString(sb)
        out = sb.toString()
        assertEquals("255 15 14 " + Base64.getEncoder().encodeToString(key), out)
        set("multiline")
        sb = StringBuilder()
        tc.rrToString(sb)
        out = sb.toString()
        assertEquals(
            "255 15 14 (" + LINE_SEPARATOR + Base64.getMimeEncoder().encodeToString(key) + LINE_SEPARATOR + ") ; key_tag = 18509",
            out
        )
        unset("multiline")
    }

    @Throws(TextParseException::class)
    fun test_getFootprint() {
        val n = fromString("my.name.")
        val key = byteArrayOf(0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF)
        var tc = TestClass(n, DnsRecordType.KEY, DnsClass.IN, 100L, 0xFF, 0xF, DNSSEC.Algorithm.RSAMD5, key)
        var foot = tc.footprint
        // second-to-last and third-to-last bytes of key for RSAMD5
        assertEquals(0xD0E, foot)
        assertEquals(foot, tc.footprint)

        // key with an odd number of bytes
        tc = TestClass(n, DnsRecordType.KEY, DnsClass.IN, 100L, 0x89AB, 0xCD, 0xEF, byteArrayOf(0x12, 0x34, 0x56))

        // rrToWire gives: { 0x89, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56 }
        // 89AB + CDEF + 1234 + 5600 = 1BCFE
        // 1BFCE + 1 = 1BFCF & FFFF = BFCF
        foot = tc.footprint
        assertEquals(0xBFCF, foot)
        assertEquals(foot, tc.footprint)

        // empty
        tc = TestClass()
        assertEquals(0, tc.footprint)
    }

    @Throws(IOException::class, TextParseException::class)
    fun test_rrToWire() {
        val n = fromString("my.name.")
        val key = byteArrayOf(0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF)
        val tc = TestClass(n, DnsRecordType.KEY, DnsClass.IN, 100L, 0x7689, 0xAB, 0xCD, key)
        val exp =
            byteArrayOf(0x76.toByte(), 0x89.toByte(), 0xAB.toByte(), 0xCD.toByte(), 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
        var o = DnsOutput()

        // canonical
        tc.rrToWire(o, null, true)
        assertTrue(Arrays.equals(exp, o.toByteArray()))

        // not canonical
        o = DnsOutput()
        tc.rrToWire(o, null, false)
        assertTrue(Arrays.equals(exp, o.toByteArray()))
    }
}
