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
import dorkbox.dns.dns.Name.Companion.fromString
import dorkbox.dns.dns.constants.DnsClass
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.exceptions.TextParseException
import junit.framework.TestCase
import java.util.*

class MXRecordTest : TestCase() {
    fun test_getObject() {
        val d = MXRecord()
        val r = d.dnsRecord
        assertTrue(r is MXRecord)
    }

    @Throws(TextParseException::class)
    fun test_ctor_5arg() {
        val n = fromString("My.Name.")
        val m = fromString("My.OtherName.")
        val d = MXRecord(n, DnsClass.IN, 0xABCDEL, 0xF1, m)
        assertEquals(n, d.name)
        assertEquals(DnsRecordType.MX, d.type)
        assertEquals(DnsClass.IN, d.dclass)
        assertEquals(0xABCDEL, d.ttl)
        assertEquals(0xF1, d.priority)
        assertEquals(m, d.target)
        assertEquals(m, d.additionalName)
    }

    @Throws(TextParseException::class)
    fun test_rrToWire() {
        val n = fromString("My.Name.")
        val m = fromString("M.O.n.")
        val mr = MXRecord(n, DnsClass.IN, 0xB12FL, 0x1F2B, m)

        // canonical
        var dout = DnsOutput()
        mr.rrToWire(dout, null, true)
        var out = dout.toByteArray()
        var exp = byteArrayOf(0x1F, 0x2B, 1, 'm'.code.toByte(), 1, 'o'.code.toByte(), 1, 'n'.code.toByte(), 0)
        assertTrue(Arrays.equals(exp, out))

        // case sensitive
        dout = DnsOutput()
        mr.rrToWire(dout, null, false)
        out = dout.toByteArray()
        exp = byteArrayOf(0x1F, 0x2B, 1, 'M'.code.toByte(), 1, 'O'.code.toByte(), 1, 'n'.code.toByte(), 0)
        assertTrue(Arrays.equals(exp, out))
    }
}
