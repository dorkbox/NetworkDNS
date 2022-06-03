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

class HINFORecordTest : TestCase() {
    fun test_ctor_0arg() {
        val dr = HINFORecord()
        try {
            // name isn't initialized yet!
            assertNull(dr.name)
            fail("Name should not be initialized!")
        } catch (ignored: Exception) {
        }
        assertEquals(0, dr.type)
        assertEquals(0, dr.dclass)
        assertEquals(0, dr.ttl)
    }

    fun test_getObject() {
        val dr = HINFORecord()
        val r = dr.`object`
        assertTrue(r is HINFORecord)
    }

    @Throws(TextParseException::class)
    fun test_ctor_5arg() {
        val n = fromString("The.Name.")
        val ttl = 0xABCDL
        val cpu = "i686 Intel(R) Pentium(R) M processor 1.70GHz GenuineIntel GNU/Linux"
        val os = "Linux troy 2.6.10-gentoo-r6 #8 Wed Apr 6 21:25:04 MDT 2005"
        val dr = HINFORecord(n, DnsClass.IN, ttl, cpu, os)
        assertEquals(n, dr.name)
        assertEquals(DnsClass.IN, dr.dclass)
        assertEquals(DnsRecordType.HINFO, dr.type)
        assertEquals(ttl, dr.ttl)
        assertEquals(cpu, dr.cPU)
        assertEquals(os, dr.oS)
    }

    @Throws(TextParseException::class)
    fun test_ctor_5arg_invalid_CPU() {
        val n = fromString("The.Name.")
        val ttl = 0xABCDL
        val cpu = "i686 Intel(R) Pentium(R) M \\256 processor 1.70GHz GenuineIntel GNU/Linux"
        val os = "Linux troy 2.6.10-gentoo-r6 #8 Wed Apr 6 21:25:04 MDT 2005"
        try {
            HINFORecord(n, DnsClass.IN, ttl, cpu, os)
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
        }
    }

    @Throws(TextParseException::class)
    fun test_ctor_5arg_invalid_OS() {
        val n = fromString("The.Name.")
        val ttl = 0xABCDL
        val cpu = "i686 Intel(R) Pentium(R) M processor 1.70GHz GenuineIntel GNU/Linux"
        val os = "Linux troy 2.6.10-gentoo-r6 \\1 #8 Wed Apr 6 21:25:04 MDT 2005"
        try {
            HINFORecord(n, DnsClass.IN, ttl, cpu, os)
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
        }
    }

    @Throws(IOException::class)
    fun test_rrFromWire() {
        val cpu = "Intel(R) Pentium(R) M processor 1.70GHz"
        val os = "Linux troy 2.6.10-gentoo-r6"
        val raw = byteArrayOf(
            39,
            'I'.code.toByte(),
            'n'.code.toByte(),
            't'.code.toByte(),
            'e'.code.toByte(),
            'l'.code.toByte(),
            '('.code.toByte(),
            'R'.code.toByte(),
            ')'.code.toByte(),
            ' '.code.toByte(),
            'P'.code.toByte(),
            'e'.code.toByte(),
            'n'.code.toByte(),
            't'.code.toByte(),
            'i'.code.toByte(),
            'u'.code.toByte(),
            'm'.code.toByte(),
            '('.code.toByte(),
            'R'.code.toByte(),
            ')'.code.toByte(),
            ' '.code.toByte(),
            'M'.code.toByte(),
            ' '.code.toByte(),
            'p'.code.toByte(),
            'r'.code.toByte(),
            'o'.code.toByte(),
            'c'.code.toByte(),
            'e'.code.toByte(),
            's'.code.toByte(),
            's'.code.toByte(),
            'o'.code.toByte(),
            'r'.code.toByte(),
            ' '.code.toByte(),
            '1'.code.toByte(),
            '.'.code.toByte(),
            '7'.code.toByte(),
            '0'.code.toByte(),
            'G'.code.toByte(),
            'H'.code.toByte(),
            'z'.code.toByte(),
            27,
            'L'.code.toByte(),
            'i'.code.toByte(),
            'n'.code.toByte(),
            'u'.code.toByte(),
            'x'.code.toByte(),
            ' '.code.toByte(),
            't'.code.toByte(),
            'r'.code.toByte(),
            'o'.code.toByte(),
            'y'.code.toByte(),
            ' '.code.toByte(),
            '2'.code.toByte(),
            '.'.code.toByte(),
            '6'.code.toByte(),
            '.'.code.toByte(),
            '1'.code.toByte(),
            '0'.code.toByte(),
            '-'.code.toByte(),
            'g'.code.toByte(),
            'e'.code.toByte(),
            'n'.code.toByte(),
            't'.code.toByte(),
            'o'.code.toByte(),
            'o'.code.toByte(),
            '-'.code.toByte(),
            'r'.code.toByte(),
            '6'.code.toByte()
        )
        val `in` = DnsInput(raw)
        val dr = HINFORecord()
        dr.rrFromWire(`in`)
        assertEquals(cpu, dr.cPU)
        assertEquals(os, dr.oS)
    }

    @Throws(IOException::class)
    fun test_rdataFromString() {
        val cpu = "Intel(R) Pentium(R) M processor 1.70GHz"
        val os = "Linux troy 2.6.10-gentoo-r6"
        val t = Tokenizer("\"$cpu\" \"$os\"")
        val dr = HINFORecord()
        dr.rdataFromString(t, null)
        assertEquals(cpu, dr.cPU)
        assertEquals(os, dr.oS)
    }

    @Throws(IOException::class)
    fun test_rdataFromString_invalid_CPU() {
        val cpu = "Intel(R) Pentium(R) \\388 M processor 1.70GHz"
        val os = "Linux troy 2.6.10-gentoo-r6"
        val t = Tokenizer("\"$cpu\" \"$os\"")
        val dr = HINFORecord()
        try {
            dr.rdataFromString(t, null)
            fail("TextParseException not thrown")
        } catch (e: TextParseException) {
        }
    }

    @Throws(IOException::class)
    fun test_rdataFromString_invalid_OS() {
        val cpu = "Intel(R) Pentium(R) M processor 1.70GHz"
        val t = Tokenizer("\"" + cpu + "\"")
        val dr = HINFORecord()
        try {
            dr.rdataFromString(t, null)
            fail("TextParseException not thrown")
        } catch (e: TextParseException) {
        }
    }

    @Throws(TextParseException::class)
    fun test_rrToString() {
        val cpu = "Intel(R) Pentium(R) M processor 1.70GHz"
        val os = "Linux troy 2.6.10-gentoo-r6"
        val exp = "\"$cpu\" \"$os\""
        val dr = HINFORecord(fromString("The.Name."), DnsClass.IN, 0x123, cpu, os)
        val sb = StringBuilder()
        dr.rrToString(sb)
        assertEquals(exp, sb.toString())
    }

    @Throws(TextParseException::class)
    fun test_rrToWire() {
        val cpu = "Intel(R) Pentium(R) M processor 1.70GHz"
        val os = "Linux troy 2.6.10-gentoo-r6"
        val raw = byteArrayOf(
            39,
            'I'.code.toByte(),
            'n'.code.toByte(),
            't'.code.toByte(),
            'e'.code.toByte(),
            'l'.code.toByte(),
            '('.code.toByte(),
            'R'.code.toByte(),
            ')'.code.toByte(),
            ' '.code.toByte(),
            'P'.code.toByte(),
            'e'.code.toByte(),
            'n'.code.toByte(),
            't'.code.toByte(),
            'i'.code.toByte(),
            'u'.code.toByte(),
            'm'.code.toByte(),
            '('.code.toByte(),
            'R'.code.toByte(),
            ')'.code.toByte(),
            ' '.code.toByte(),
            'M'.code.toByte(),
            ' '.code.toByte(),
            'p'.code.toByte(),
            'r'.code.toByte(),
            'o'.code.toByte(),
            'c'.code.toByte(),
            'e'.code.toByte(),
            's'.code.toByte(),
            's'.code.toByte(),
            'o'.code.toByte(),
            'r'.code.toByte(),
            ' '.code.toByte(),
            '1'.code.toByte(),
            '.'.code.toByte(),
            '7'.code.toByte(),
            '0'.code.toByte(),
            'G'.code.toByte(),
            'H'.code.toByte(),
            'z'.code.toByte(),
            27,
            'L'.code.toByte(),
            'i'.code.toByte(),
            'n'.code.toByte(),
            'u'.code.toByte(),
            'x'.code.toByte(),
            ' '.code.toByte(),
            't'.code.toByte(),
            'r'.code.toByte(),
            'o'.code.toByte(),
            'y'.code.toByte(),
            ' '.code.toByte(),
            '2'.code.toByte(),
            '.'.code.toByte(),
            '6'.code.toByte(),
            '.'.code.toByte(),
            '1'.code.toByte(),
            '0'.code.toByte(),
            '-'.code.toByte(),
            'g'.code.toByte(),
            'e'.code.toByte(),
            'n'.code.toByte(),
            't'.code.toByte(),
            'o'.code.toByte(),
            'o'.code.toByte(),
            '-'.code.toByte(),
            'r'.code.toByte(),
            '6'.code.toByte()
        )
        val dr = HINFORecord(fromString("The.Name."), DnsClass.IN, 0x123, cpu, os)
        val out = DnsOutput()
        dr.rrToWire(out, null, true)
        assertTrue(Arrays.equals(raw, out.toByteArray()))
    }
}
