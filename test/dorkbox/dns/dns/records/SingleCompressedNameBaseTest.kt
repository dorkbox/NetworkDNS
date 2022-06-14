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

import dorkbox.dns.dns.DnsOutput
import dorkbox.dns.dns.Name
import dorkbox.dns.dns.Name.Companion.fromString
import dorkbox.dns.dns.constants.DnsClass
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.exceptions.TextParseException
import junit.framework.TestCase
import java.io.IOException
import java.util.*

class SingleCompressedNameBaseTest : TestCase() {
    private class TestClass : SingleCompressedNameBase {
        constructor()
        constructor(name: Name, type: Int, dclass: Int, ttl: Long, singleName: Name, desc: String) : super(
            name, type, dclass, ttl, singleName, desc
        )

        override val dnsRecord: DnsRecord
            get() = this
    }

    @Throws(TextParseException::class)
    fun test_ctor() {
        var tc = TestClass()
        try {
            // name isn't initialized yet!
            assertNull(tc.singleName)
            fail("Name should not be initialized!")
        } catch (ignored: Exception) {
        }

        val n = fromString("my.name.")
        val sn = fromString("my.single.name.")
        tc = TestClass(n, DnsRecordType.A, DnsClass.IN, 100L, sn, "The Description")
        assertSame(n, tc.name)
        assertEquals(DnsRecordType.A, tc.type)
        assertEquals(DnsClass.IN, tc.dclass)
        assertEquals(100L, tc.ttl)
        assertSame(sn, tc.singleName)
    }

    @Throws(IOException::class, TextParseException::class)
    fun test_rrToWire() {
        val n = fromString("my.name.")
        val sn = fromString("My.Single.Name.")

        // non-canonical (case sensitive)
        var tc = TestClass(n, DnsRecordType.A, DnsClass.IN, 100L, sn, "The Description")
        var exp = byteArrayOf(
            2,
            'M'.code.toByte(),
            'y'.code.toByte(),
            6,
            'S'.code.toByte(),
            'i'.code.toByte(),
            'n'.code.toByte(),
            'g'.code.toByte(),
            'l'.code.toByte(),
            'e'.code.toByte(),
            4,
            'N'.code.toByte(),
            'a'.code.toByte(),
            'm'.code.toByte(),
            'e'.code.toByte(),
            0
        )
        var dout = DnsOutput()
        tc.rrToWire(dout, null, false)
        var out = dout.toByteArray()
        assertEquals(exp, out)

        // canonical (lowercase)
        tc = TestClass(n, DnsRecordType.A, DnsClass.IN, 100L, sn, "The Description")
        exp = byteArrayOf(
            2,
            'm'.code.toByte(),
            'y'.code.toByte(),
            6,
            's'.code.toByte(),
            'i'.code.toByte(),
            'n'.code.toByte(),
            'g'.code.toByte(),
            'l'.code.toByte(),
            'e'.code.toByte(),
            4,
            'n'.code.toByte(),
            'a'.code.toByte(),
            'm'.code.toByte(),
            'e'.code.toByte(),
            0
        )
        dout = DnsOutput()
        tc.rrToWire(dout, null, true)
        out = dout.toByteArray()
        assertEquals(exp, out)
    }

    private fun assertEquals(exp: ByteArray, act: ByteArray) {
        assertTrue(Arrays.equals(exp, act))
    }
}
