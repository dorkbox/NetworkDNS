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
import java.util.*

class U16NameBaseTest : TestCase() {
    private fun assertEquals(exp: ByteArray, act: ByteArray) {
        assertTrue(Arrays.equals(exp, act))
    }

    private class TestClass : U16NameBase {
        constructor()
        constructor(name: Name?, type: Int, dclass: Int, ttl: Long) : super(name!!, type, dclass, ttl)
        constructor(
            name: Name,
            type: Int,
            dclass: Int,
            ttl: Long,
            u16Field: Int,
            u16Description: String,
            nameField: Name,
            nameDescription: String
        ) : super(
            name, type, dclass, ttl, u16Field, u16Description, nameField, nameDescription
        ) {
        }

        override val `object`: DnsRecord
            get() = this
    }

    fun test_ctor_0arg() {
        val tc = TestClass()
        try {
            // name isn't initialized yet!
            assertNull(tc.name)
            fail("Name should not be initialized!")
        } catch (ignored: Exception) {
        }

        assertEquals(0, tc.type)
        assertEquals(0, tc.dclass)
        assertEquals(0, tc.ttl)
        assertEquals(0, tc.u16Field)

        try {
            // name isn't initialized yet!
            assertNull(tc.nameField)
            fail("Name should not be initialized!")
        } catch (ignored: Exception) {
        }
    }

    @Throws(TextParseException::class)
    fun test_ctor_4arg() {
        val n = fromString("My.Name.")
        val tc = TestClass(n, DnsRecordType.MX, DnsClass.IN, 0xBCDA)
        assertSame(n, tc.name)
        assertEquals(DnsRecordType.MX, tc.type)
        assertEquals(DnsClass.IN, tc.dclass)
        assertEquals(0xBCDA, tc.ttl)
        assertEquals(0, tc.u16Field)

        try {
            // namefield isn't initialized yet!
            assertNull(tc.nameField)
            fail("Name should not be initialized!")
        } catch (ignored: Exception) {
        }
    }

    @Throws(TextParseException::class)
    fun test_ctor_8arg() {
        val n = fromString("My.Name.")
        val m = fromString("My.Other.Name.")
        val tc = TestClass(n, DnsRecordType.MX, DnsClass.IN, 0xB12FL, 0x1F2B, "u16 description", m, "name description")
        assertSame(n, tc.name)
        assertEquals(DnsRecordType.MX, tc.type)
        assertEquals(DnsClass.IN, tc.dclass)
        assertEquals(0xB12FL, tc.ttl)
        assertEquals(0x1F2B, tc.u16Field)
        assertEquals(m, tc.nameField)

        // an invalid u16 value
        try {
            TestClass(n, DnsRecordType.MX, DnsClass.IN, 0xB12FL, 0x10000, "u16 description", m, "name description")
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }

        // a relative name
        val rel = fromString("My.relative.Name")
        try {
            TestClass(n, DnsRecordType.MX, DnsClass.IN, 0xB12FL, 0x1F2B, "u16 description", rel, "name description")
            fail("RelativeNameException not thrown")
        } catch (ignored: RelativeNameException) {
        }
    }

    @Throws(IOException::class)
    fun test_rrFromWire() {
        val raw = byteArrayOf(
            0xBC.toByte(),
            0x1F.toByte(),
            2,
            'M'.code.toByte(),
            'y'.code.toByte(),
            6,
            's'.code.toByte(),
            'i'.code.toByte(),
            'N'.code.toByte(),
            'g'.code.toByte(),
            'l'.code.toByte(),
            'E'.code.toByte(),
            4,
            'n'.code.toByte(),
            'A'.code.toByte(),
            'm'.code.toByte(),
            'E'.code.toByte(),
            0
        )

        val `in` = DnsInput(raw)
        val tc = TestClass()
        tc.rrFromWire(`in`)
        val exp = fromString("My.single.name.")
        assertEquals(0xBC1FL, tc.u16Field.toLong())
        assertEquals(exp, tc.nameField)
    }

    @Throws(IOException::class)
    fun test_rdataFromString() {
        val exp = fromString("My.Single.Name.")
        var t = Tokenizer(0x19A2.toString() + " My.Single.Name.")
        var tc = TestClass()
        tc.rdataFromString(t, null)
        assertEquals(0x19A2, tc.u16Field)
        assertEquals(exp, tc.nameField)

        t = Tokenizer("10 My.Relative.Name")
        tc = TestClass()

        try {
            tc.rdataFromString(t, null)
            fail("RelativeNameException not thrown")
        } catch (ignored: RelativeNameException) {
        }
    }

    @Throws(IOException::class, TextParseException::class)
    fun test_rrToString() {
        val n = fromString("My.Name.")
        val m = fromString("My.Other.Name.")
        val tc = TestClass(n, DnsRecordType.MX, DnsClass.IN, 0xB12FL, 0x1F2B, "u16 description", m, "name description")
        val sb = StringBuilder()
        tc.rrToString(sb)
        val out = sb.toString()
        val exp = 0x1F2B.toString() + " My.Other.Name."

        assertEquals(exp, out)
    }

    @Throws(IOException::class, TextParseException::class)
    fun test_rrToWire() {
        val n = fromString("My.Name.")
        val m = fromString("M.O.n.")
        val tc = TestClass(n, DnsRecordType.MX, DnsClass.IN, 0xB12FL, 0x1F2B, "u16 description", m, "name description")

        // canonical
        var dout = DnsOutput()
        tc.rrToWire(dout, null, true)
        var out = dout.toByteArray()
        var exp = byteArrayOf(0x1F, 0x2B, 1, 'm'.code.toByte(), 1, 'o'.code.toByte(), 1, 'n'.code.toByte(), 0)
        assertTrue(Arrays.equals(exp, out))

        // case sensitive
        dout = DnsOutput()
        tc.rrToWire(dout, null, false)
        out = dout.toByteArray()
        exp = byteArrayOf(0x1F, 0x2B, 1, 'M'.code.toByte(), 1, 'O'.code.toByte(), 1, 'n'.code.toByte(), 0)
        assertTrue(Arrays.equals(exp, out))
    }
}
