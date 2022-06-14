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

import dorkbox.dns.dns.Compression
import dorkbox.dns.dns.DnsInput
import dorkbox.dns.dns.DnsOutput
import dorkbox.dns.dns.Name
import dorkbox.dns.dns.Name.Companion.fromString
import dorkbox.dns.dns.constants.DnsClass
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.constants.DnsSection
import dorkbox.dns.dns.exceptions.InvalidDClassException
import dorkbox.dns.dns.exceptions.InvalidTTLException
import dorkbox.dns.dns.exceptions.InvalidTypeException
import dorkbox.dns.dns.exceptions.RelativeNameException
import dorkbox.dns.dns.exceptions.TextParseException
import dorkbox.dns.dns.records.DnsRecord.Companion.byteArrayFromString
import dorkbox.dns.dns.records.DnsRecord.Companion.byteArrayToString
import dorkbox.dns.dns.records.DnsRecord.Companion.checkName
import dorkbox.dns.dns.records.DnsRecord.Companion.checkU16
import dorkbox.dns.dns.records.DnsRecord.Companion.checkU32
import dorkbox.dns.dns.records.DnsRecord.Companion.checkU8
import dorkbox.dns.dns.records.DnsRecord.Companion.fromString
import dorkbox.dns.dns.records.DnsRecord.Companion.fromWire
import dorkbox.dns.dns.records.DnsRecord.Companion.newRecord
import dorkbox.dns.dns.records.DnsRecord.Companion.unknownToString
import dorkbox.dns.dns.records.TTL.format
import dorkbox.dns.dns.utils.Options.set
import dorkbox.dns.dns.utils.Tokenizer
import junit.framework.TestCase
import java.io.IOException
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.*

class RecordTest : TestCase() {
    private class SubRecord : DnsRecord {
        constructor() {}
        constructor(name: Name?, type: Int, dclass: Int, ttl: Long) : super(name!!, type, dclass, ttl) {}

        override val dnsRecord: DnsRecord
            get() = this

        @Throws(IOException::class)
        override fun rrFromWire(`in`: DnsInput) {
        }

        override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {}
        override fun rrToString(sb: StringBuilder) {
            sb.append("{SubRecord: rrToString}")
        }

        @Throws(IOException::class)
        override fun rdataFromString(t: Tokenizer, origin: Name?) {
        }

        override fun clone(): Any {
            throw CloneNotSupportedException()
        }
    }

    fun test_ctor_0arg() {
        val sr = SubRecord()
        try {
            // name isn't initialized yet!
            assertNull(sr.name)
            fail("Name should not be initialized!")
        } catch (ignored: Exception) {
        }
        assertEquals(0, sr.type)
        assertEquals(0, sr.ttl)
        assertEquals(0, sr.dclass)
    }

    @Throws(TextParseException::class)
    fun test_ctor_4arg() {
        val n = fromString("my.name.")
        val t = DnsRecordType.A
        val d = DnsClass.IN
        val ttl = 0xABCDEL
        val r = SubRecord(n, t, d, ttl)
        assertEquals(n, r.name)
        assertEquals(t, r.type)
        assertEquals(d, r.dclass)
        assertEquals(ttl, r.ttl)
    }

    @Throws(TextParseException::class)
    fun test_ctor_4arg_invalid() {
        val n = fromString("my.name.")
        val r = fromString("my.relative.name")
        val t = DnsRecordType.A
        val d = DnsClass.IN
        val ttl = 0xABCDEL
        try {
            SubRecord(r, t, d, ttl)
            fail("RelativeNameException not thrown")
        } catch (ignored: RelativeNameException) {
        }
        try {
            SubRecord(n, -1, d, ttl)
            fail("InvalidTypeException not thrown")
        } catch (ignored: InvalidTypeException) {
        }
        try {
            SubRecord(n, t, -1, ttl)
            fail("InvalidDClassException not thrown")
        } catch (ignored: InvalidDClassException) {
        }
        try {
            SubRecord(n, t, d, -1)
            fail("InvalidTTLException not thrown")
        } catch (ignored: InvalidTTLException) {
        }
    }

    @Throws(TextParseException::class)
    fun test_newRecord_3arg() {
        val n = fromString("my.name.")
        val r = fromString("my.relative.name")
        val t = DnsRecordType.A
        val d = DnsClass.IN
        val rec = newRecord(n, t, d, 0L)
        assertTrue(rec is EmptyRecord)
        assertEquals(n, rec.name)
        assertEquals(t, rec.type)
        assertEquals(d, rec.dclass)
        assertEquals(0, rec.ttl)
        try {
            newRecord(r, t, d, 0L)
            fail("RelativeNameException not thrown")
        } catch (ignored: RelativeNameException) {
        }
    }

    @Throws(TextParseException::class)
    fun test_newRecord_4arg() {
        val n = fromString("my.name.")
        val r = fromString("my.relative.name")
        val t = DnsRecordType.A
        val d = DnsClass.IN
        val ttl = 0xDBE8
        val rec = newRecord(n, t, d, ttl.toLong())
        assertTrue(rec is EmptyRecord)
        assertEquals(n, rec.name)
        assertEquals(t, rec.type)
        assertEquals(d, rec.dclass)
        assertEquals(ttl.toLong(), rec.ttl)
        try {
            newRecord(r, t, d, ttl.toLong())
            fail("RelativeNameException not thrown")
        } catch (ignored: RelativeNameException) {
        }
    }

    @Throws(TextParseException::class, UnknownHostException::class)
    fun test_newRecord_5arg() {
        val n = fromString("my.name.")
        val t = DnsRecordType.A
        val d = DnsClass.IN
        val ttl = 0xDBE8
        val data = byteArrayOf(123.toByte(), 232.toByte(), 0.toByte(), 255.toByte())
        val exp = InetAddress.getByName("123.232.0.255")
        val rec = newRecord(n, t, d, ttl.toLong(), data)
        assertTrue(rec is ARecord)
        assertEquals(n, rec!!.name)
        assertEquals(t, rec.type)
        assertEquals(d, rec.dclass)
        assertEquals(ttl.toLong(), rec.ttl)
        assertEquals(exp, (rec as ARecord?)!!.address)
    }

    @Throws(TextParseException::class, UnknownHostException::class)
    fun test_newRecord_6arg() {
        val n = fromString("my.name.")
        val t = DnsRecordType.A
        val d = DnsClass.IN
        val ttl = 0xDBE8
        val data = byteArrayOf(123.toByte(), 232.toByte(), 0.toByte(), 255.toByte())
        val exp = InetAddress.getByName("123.232.0.255")
        var rec = newRecord(n, t, d, ttl.toLong(), 0, byteArrayOf())
        assertTrue(rec is EmptyRecord)
        assertEquals(n, rec!!.name)
        assertEquals(t, rec.type)
        assertEquals(d, rec.dclass)
        assertEquals(ttl.toLong(), rec.ttl)
        rec = newRecord(n, t, d, ttl.toLong(), data.size, data)
        assertTrue(rec is ARecord)
        assertEquals(n, rec!!.name)
        assertEquals(t, rec.type)
        assertEquals(d, rec.dclass)
        assertEquals(ttl.toLong(), rec.ttl)
        assertEquals(exp, (rec as ARecord?)!!.address)
        rec = newRecord(n, DnsRecordType.NIMLOC, d, ttl.toLong(), data.size, data)
        assertTrue(rec is UNKRecord)
        assertEquals(n, rec!!.name)
        assertEquals(DnsRecordType.NIMLOC, rec.type)
        assertEquals(d, rec.dclass)
        assertEquals(ttl.toLong(), rec.ttl)
        assertTrue(Arrays.equals(data, (rec as UNKRecord?)!!.data))
    }

    @Throws(TextParseException::class)
    fun test_newRecord_6arg_invalid() {
        val n = fromString("my.name.")
        val r = fromString("my.relative.name")
        val t = DnsRecordType.A
        val d = DnsClass.IN
        val ttl = 0xDBE8
        val data = byteArrayOf(123.toByte(), 232.toByte(), 0.toByte(), 255.toByte())
        assertNull(newRecord(n, t, d, ttl.toLong(), 0, ByteArray(0)))
        assertNull(newRecord(n, t, d, ttl.toLong(), 1, ByteArray(0)))
        assertNull(newRecord(n, t, d, ttl.toLong(), data.size + 1, data))
        assertNull(newRecord(n, t, d, ttl.toLong(), 5, byteArrayOf(data[0], data[1], data[2], data[3], 0)))
        try {
            newRecord(r, t, d, ttl.toLong(), 0, byteArrayOf())
            fail("RelativeNameException not thrown")
        } catch (ignored: RelativeNameException) {
        }
    }

    @Throws(IOException::class, TextParseException::class, UnknownHostException::class)
    fun test_fromWire() {
        val n = fromString("my.name.")
        val t = DnsRecordType.A
        val d = DnsClass.IN
        val ttl = 0xDBE8
        val data = byteArrayOf(123.toByte(), 232.toByte(), 0.toByte(), 255.toByte())
        val exp = InetAddress.getByName("123.232.0.255")
        var out = DnsOutput()
        n.toWire(out, null)
        out.writeU16(t)
        out.writeU16(d)
        out.writeU32(ttl.toLong())
        out.writeU16(data.size)
        out.writeByteArray(data)
        val bytes = out.toByteArray()
        var `in` = DnsInput(bytes)
        var rec = fromWire(`in`, DnsSection.ANSWER, false)
        assertTrue(rec is ARecord)
        assertEquals(n, rec.name)
        assertEquals(t, rec.type)
        assertEquals(d, rec.dclass)
        assertEquals(ttl.toLong(), rec.ttl)
        assertEquals(exp, (rec as ARecord).address)
        `in` = DnsInput(bytes)
        rec = fromWire(`in`, DnsSection.QUESTION, false)
        assertTrue(rec is EmptyRecord)
        assertEquals(n, rec.name)
        assertEquals(t, rec.type)
        assertEquals(d, rec.dclass)
        assertEquals(0, rec.ttl)
        `in` = DnsInput(bytes)
        rec = fromWire(`in`, DnsSection.QUESTION, false)
        assertTrue(rec is EmptyRecord)
        assertEquals(n, rec.name)
        assertEquals(t, rec.type)
        assertEquals(d, rec.dclass)
        assertEquals(0, rec.ttl)
        rec = fromWire(bytes, DnsSection.QUESTION)
        assertTrue(rec is EmptyRecord)
        assertEquals(n, rec.name)
        assertEquals(t, rec.type)
        assertEquals(d, rec.dclass)
        assertEquals(0, rec.ttl)
        out = DnsOutput()
        n.toWire(out, null)
        out.writeU16(t)
        out.writeU16(d)
        out.writeU32(ttl.toLong())
        out.writeU16(0)
        `in` = DnsInput(out.toByteArray())
        rec = fromWire(`in`, DnsSection.ANSWER, true)
        assertTrue(rec is EmptyRecord)
        assertEquals(n, rec.name)
        assertEquals(t, rec.type)
        assertEquals(d, rec.dclass)
        assertEquals(ttl.toLong(), rec.ttl)
    }

    @Throws(IOException::class, TextParseException::class, UnknownHostException::class)
    fun test_toWire() {
        val n = fromString("my.name.")
        val t = DnsRecordType.A
        val d = DnsClass.IN
        val ttl = 0xDBE8
        val data = byteArrayOf(123.toByte(), 232.toByte(), 0.toByte(), 255.toByte())

        // a non-QUESTION
        var out = DnsOutput()
        n.toWire(out, null)
        out.writeU16(t)
        out.writeU16(d)
        out.writeU32(ttl.toLong())
        out.writeU16(data.size)
        out.writeByteArray(data)
        var exp = out.toByteArray()
        val rec = newRecord(n, t, d, ttl.toLong(), data.size, data)
        out = DnsOutput()
        rec!!.toWire(out, DnsSection.ANSWER, null)
        var after = out.toByteArray()
        assertTrue(Arrays.equals(exp, after))

        // an equivalent call
        after = rec.toWire(DnsSection.ANSWER)
        assertTrue(Arrays.equals(exp, after))

        // a QUESTION entry
        out = DnsOutput()
        n.toWire(out, null)
        out.writeU16(t)
        out.writeU16(d)
        exp = out.toByteArray()
        out = DnsOutput()
        rec.toWire(out, DnsSection.QUESTION, null)
        after = out.toByteArray()
        assertTrue(Arrays.equals(exp, after))
    }

    @Throws(IOException::class, TextParseException::class, UnknownHostException::class)
    fun test_toWireCanonical() {
        val n = fromString("My.Name.")
        val t = DnsRecordType.A
        val d = DnsClass.IN
        val ttl = 0xDBE8
        val data = byteArrayOf(123.toByte(), 232.toByte(), 0.toByte(), 255.toByte())
        val out = DnsOutput()
        n.toWireCanonical(out)
        out.writeU16(t)
        out.writeU16(d)
        out.writeU32(ttl.toLong())
        out.writeU16(data.size)
        out.writeByteArray(data)
        val exp = out.toByteArray()
        val rec = newRecord(n, t, d, ttl.toLong(), data.size, data)
        val after = rec!!.toWireCanonical()
        assertTrue(Arrays.equals(exp, after))
    }

    @Throws(IOException::class, TextParseException::class, UnknownHostException::class)
    fun test_rdataToWireCanonical() {
        val n = fromString("My.Name.")
        val n2 = fromString("My.Second.Name.")
        val t = DnsRecordType.NS
        val d = DnsClass.IN
        val ttl = 0xABE99
        var out = DnsOutput()
        n2.toWire(out, null)
        val data = out.toByteArray()
        out = DnsOutput()
        n2.toWireCanonical(out)
        val exp = out.toByteArray()
        val rec = newRecord(n, t, d, ttl.toLong(), data.size, data)
        assertTrue(rec is NSRecord)
        val after = rec!!.rdataToWireCanonical()
        assertTrue(Arrays.equals(exp, after))
    }

    @Throws(IOException::class, TextParseException::class, UnknownHostException::class)
    fun test_rdataToString() {
        val n = fromString("My.Name.")
        val n2 = fromString("My.Second.Name.")
        val t = DnsRecordType.NS
        val d = DnsClass.IN
        val ttl = 0xABE99
        val out = DnsOutput()
        n2.toWire(out, null)
        val data = out.toByteArray()
        val rec = newRecord(n, t, d, ttl.toLong(), data.size, data)
        assertTrue(rec is NSRecord)
        val sa = StringBuilder()
        rec!!.rrToString(sa)
        val sb = StringBuilder()
        rec.rdataToString(sb)
        assertEquals(sa.toString(), sb.toString())
    }

    @Throws(TextParseException::class)
    fun test_toString() {
        val n = fromString("My.N.")
        val n2 = fromString("My.Second.Name.")
        val t = DnsRecordType.NS
        val d = DnsClass.IN
        val ttl = 0xABE99
        val o = DnsOutput()
        n2.toWire(o, null)
        val data = o.toByteArray()
        val rec = newRecord(n, t, d, ttl.toLong(), data.size, data)
        var out = rec.toString()
        assertFalse(out.indexOf(n.toString()) == -1)
        assertFalse(out.indexOf(n2.toString()) == -1)
        assertFalse(out.indexOf("NS") == -1)
        assertFalse(out.indexOf("IN") == -1)
        assertFalse(out.indexOf(ttl.toString() + "") == -1)
        set("BINDTTL")
        out = rec.toString()
        assertFalse(out.indexOf(n.toString()) == -1)
        assertFalse(out.indexOf(n2.toString()) == -1)
        assertFalse(out.indexOf("NS") == -1)
        assertFalse(out.indexOf("IN") == -1)
        assertFalse(out.indexOf(format(ttl.toLong())) == -1)
        set("noPrintIN")
        out = rec.toString()
        assertFalse(out.indexOf(n.toString()) == -1)
        assertFalse(out.indexOf(n2.toString()) == -1)
        assertFalse(out.indexOf("NS") == -1)
        assertTrue(out.indexOf("IN") == -1)
        assertFalse(out.indexOf(format(ttl.toLong())) == -1)
    }

    @Throws(TextParseException::class)
    fun test_byteArrayFromString() {
        var `in` = "the 98 \" \' quick 0xAB brown"
        var out = byteArrayFromString(`in`)
        assertTrue(Arrays.equals(`in`.toByteArray(), out))
        `in` = " \\031Aa\\;\\\"\\\\~\\127\\255"
        val exp = byteArrayOf(
            ' '.code.toByte(),
            0x1F,
            'A'.code.toByte(),
            'a'.code.toByte(),
            ';'.code.toByte(),
            '"'.code.toByte(),
            '\\'.code.toByte(),
            0x7E,
            0x7F,
            0xFF.toByte()
        )
        out = byteArrayFromString(`in`)
        assertTrue(Arrays.equals(exp, out))
    }

    fun test_byteArrayFromString_invalid() {
        val b = StringBuilder()
        for (i in 0..256) {
            b.append('A')
        }
        try {
            byteArrayFromString(b.toString())
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }
        try {
            byteArrayFromString("\\256")
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }
        try {
            byteArrayFromString("\\25a")
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }
        try {
            byteArrayFromString("\\25")
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }
        b.append("\\233")
        try {
            byteArrayFromString(b.toString())
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }
    }

    fun test_byteArrayToString() {
        val `in` = byteArrayOf(
            ' '.code.toByte(),
            0x1F,
            'A'.code.toByte(),
            'a'.code.toByte(),
            ';'.code.toByte(),
            '"'.code.toByte(),
            '\\'.code.toByte(),
            0x7E,
            0x7F,
            0xFF.toByte()
        )
        val exp = "\" \\031Aa;\\\"\\\\~\\127\\255\""
        assertEquals(exp, byteArrayToString(`in`, true))
    }

    fun test_unknownToString() {
        val data = byteArrayOf(
            0x12.toByte(),
            0x34.toByte(),
            0x56.toByte(),
            0x78.toByte(),
            0x9A.toByte(),
            0xBC.toByte(),
            0xDE.toByte(),
            0xFF.toByte()
        )
        val out = unknownToString(data)
        assertFalse(out.indexOf("" + data.size) == -1)
        assertFalse(out.indexOf("123456789ABCDEFF") == -1)
    }

    @Throws(IOException::class, TextParseException::class)
    fun test_fromString() {
        val n = fromString("My.N.")
        val n2 = fromString("My.Second.Name.")
        val t = DnsRecordType.A
        val d = DnsClass.IN
        val ttl = 0xABE99
        val sa = "191.234.43.10"
        val addr = InetAddress.getByName(sa)
        val b = byteArrayOf(191.toByte(), 234.toByte(), 43.toByte(), 10.toByte())
        var st: Tokenizer? = Tokenizer(sa)
        var rec = fromString(n, t, d, ttl.toLong(), st!!, n2)
        assertTrue(rec is ARecord)
        assertEquals(n, rec.name)
        assertEquals(t, rec.type)
        assertEquals(d, rec.dclass)
        assertEquals(ttl.toLong(), rec.ttl)
        assertEquals(addr, (rec as ARecord).address)
        val unkData = unknownToString(b)
        st = Tokenizer(unkData)
        rec = fromString(n, t, d, ttl.toLong(), st, n2)
        assertTrue(rec is ARecord)
        assertEquals(n, rec.name)
        assertEquals(t, rec.type)
        assertEquals(d, rec.dclass)
        assertEquals(ttl.toLong(), rec.ttl)
        assertEquals(addr, (rec as ARecord).address)
    }

    @Throws(IOException::class, TextParseException::class)
    fun test_fromString_invalid() {
        val n = fromString("My.N.")
        val rel = fromString("My.R")
        val n2 = fromString("My.Second.Name.")
        val t = DnsRecordType.A
        val d = DnsClass.IN
        val ttl = 0xABE99
        val addr = InetAddress.getByName("191.234.43.10")
        var st = Tokenizer("191.234.43.10")
        try {
            fromString(rel, t, d, ttl.toLong(), st, n2)
            fail("RelativeNameException not thrown")
        } catch (ignored: RelativeNameException) {
        }
        st = Tokenizer("191.234.43.10 another_token")
        try {
            fromString(n, t, d, ttl.toLong(), st, n2)
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }
        st = Tokenizer("\\# 100 ABCDE")
        try {
            fromString(n, t, d, ttl.toLong(), st, n2)
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }
        try {
            fromString(n, t, d, ttl.toLong(), "\\# 100", n2)
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }
    }

    @Throws(TextParseException::class)
    fun test_getRRsetType() {
        val n = fromString("My.N.")
        var r = newRecord(n, DnsRecordType.A, DnsClass.IN, 0)
        assertEquals(DnsRecordType.A, r.rRsetType)
        r = RRSIGRecord(n, DnsClass.IN, 0, DnsRecordType.A, 1, 0, Date(), Date(), 10, n, ByteArray(0))
        assertEquals(DnsRecordType.A, r.rRsetType)
    }

    @Throws(TextParseException::class)
    fun test_sameRRset() {
        val n = fromString("My.N.")
        val m = fromString("My.M.")
        var r1 = newRecord(n, DnsRecordType.A, DnsClass.IN, 0)
        var r2: DnsRecord = RRSIGRecord(n, DnsClass.IN, 0, DnsRecordType.A, 1, 0, Date(), Date(), 10, n, ByteArray(0))
        assertTrue(r1.sameRRset(r2))
        assertTrue(r2.sameRRset(r1))
        r1 = newRecord(n, DnsRecordType.A, DnsClass.HS, 0)
        r2 = RRSIGRecord(n, DnsClass.IN, 0, DnsRecordType.A, 1, 0, Date(), Date(), 10, n, ByteArray(0))
        assertFalse(r1.sameRRset(r2))
        assertFalse(r2.sameRRset(r1))
        r1 = newRecord(n, DnsRecordType.A, DnsClass.IN, 0)
        r2 = RRSIGRecord(m, DnsClass.IN, 0, DnsRecordType.A, 1, 0, Date(), Date(), 10, n, ByteArray(0))
        assertFalse(r1.sameRRset(r2))
        assertFalse(r2.sameRRset(r1))
    }

    @Throws(TextParseException::class)
    fun test_equals() {
        val n = fromString("My.N.")
        val n2 = fromString("my.n.")
        val m = fromString("My.M.")
        var r1: DnsRecord? = newRecord(n, DnsRecordType.A, DnsClass.IN, 0)
        assertFalse(r1!!.equals(null))
        assertFalse(r1.equals(Any()))
        var r2: DnsRecord? = newRecord(n, DnsRecordType.A, DnsClass.IN, 0)
        assertEquals(r1, r2)
        assertEquals(r2, r1)
        r2 = newRecord(n2, DnsRecordType.A, DnsClass.IN, 0)
        assertEquals(r1, r2)
        assertEquals(r2, r1)
        r2 = newRecord(n2, DnsRecordType.A, DnsClass.IN, 0xABCDE)
        assertEquals(r1, r2)
        assertEquals(r2, r1)
        r2 = newRecord(m, DnsRecordType.A, DnsClass.IN, 0xABCDE)
        assertFalse(r1.equals(r2))
        assertFalse(r2.equals(r1))
        r2 = newRecord(n2, DnsRecordType.MX, DnsClass.IN, 0xABCDE)
        assertFalse(r1.equals(r2))
        assertFalse(r2.equals(r1))
        r2 = newRecord(n2, DnsRecordType.A, DnsClass.CHAOS, 0xABCDE)
        assertFalse(r1.equals(r2))
        assertFalse(r2.equals(r1))
        val d1 = byteArrayOf(23, 12, 9, 129.toByte())
        val d2 = byteArrayOf(220.toByte(), 1, 131.toByte(), 212.toByte())
        r1 = newRecord(n, DnsRecordType.A, DnsClass.IN, 0xABCDE9, d1)
        r2 = newRecord(n, DnsRecordType.A, DnsClass.IN, 0xABCDE9, d1)
        assertEquals(r1, r2)
        assertEquals(r2, r1)
        r2 = newRecord(n, DnsRecordType.A, DnsClass.IN, 0xABCDE9, d2)
        assertFalse(r1!!.equals(r2))
        assertFalse(r2!!.equals(r1))
    }

    @Throws(TextParseException::class)
    fun test_hashCode() {
        val n = fromString("My.N.")
        val n2 = fromString("my.n.")
        val m = fromString("My.M.")
        val d1 = byteArrayOf(23, 12, 9, 129.toByte())
        val d2 = byteArrayOf(220.toByte(), 1, 131.toByte(), 212.toByte())
        val r1 = newRecord(n, DnsRecordType.A, DnsClass.IN, 0xABCDE9, d1)

        // same DnsDnsRecord has same hash code
        var r2 = newRecord(n, DnsRecordType.A, DnsClass.IN, 0xABCDE9, d1)
        assertEquals(r1.hashCode(), r2.hashCode())

        // case of names should not matter
        r2 = newRecord(n2, DnsRecordType.A, DnsClass.IN, 0xABCDE9, d1)
        assertEquals(r1.hashCode(), r2.hashCode())

        // different names
        r2 = newRecord(m, DnsRecordType.A, DnsClass.IN, 0xABCDE9, d1)
        assertFalse(r1.hashCode() == r2.hashCode())

        // different class
        r2 = newRecord(n, DnsRecordType.A, DnsClass.CHAOS, 0xABCDE9, d1)
        assertFalse(r1.hashCode() == r2.hashCode())

        // different TTL does not matter
        r2 = newRecord(n, DnsRecordType.A, DnsClass.IN, 0xABCDE, d1)
        assertEquals(r1.hashCode(), r2.hashCode())

        // different data
        r2 = newRecord(n, DnsRecordType.A, DnsClass.IN, 0xABCDE9, d2)
        assertFalse(r1.hashCode() == r2.hashCode())
    }

    @Throws(TextParseException::class)
    fun test_cloneRecord() {
        val n = fromString("My.N.")
        val d = byteArrayOf(23, 12, 9, 129.toByte())
        var r = newRecord(n, DnsRecordType.A, DnsClass.IN, 0xABCDE9, d)
        val r2 = r!!.cloneRecord()
        assertNotSame(r, r2)
        assertEquals(r, r2)
        r = SubRecord(n, DnsRecordType.A, DnsClass.IN, 0xABCDE9)
        try {
            r.cloneRecord()
            fail("IllegalStateException not thrown")
        } catch (ignored: IllegalStateException) {
        }
    }

    @Throws(TextParseException::class)
    fun test_withName() {
        val n = fromString("My.N.")
        val m = fromString("My.M.Name.")
        val rel = fromString("My.Relative.Name")
        val d = byteArrayOf(23, 12, 9, 129.toByte())
        val r = newRecord(n, DnsRecordType.A, DnsClass.IN, 0xABCDE9, d)
        val r1 = r!!.withName(m)
        assertEquals(m, r1.name)
        assertEquals(DnsRecordType.A, r1.type)
        assertEquals(DnsClass.IN, r1.dclass)
        assertEquals(0xABCDE9, r1.ttl)
        assertEquals((r as ARecord?)!!.address, (r1 as ARecord).address)
        try {
            r.withName(rel)
            fail("RelativeNameException not thrown")
        } catch (ignored: RelativeNameException) {
        }
    }

    @Throws(TextParseException::class)
    fun test_withDClass() {
        val n = fromString("My.N.")
        val d = byteArrayOf(23, 12, 9, 129.toByte())
        val r = newRecord(n, DnsRecordType.A, DnsClass.IN, 0xABCDE9, d)
        val r1 = r!!.withDClass(DnsClass.HESIOD, 0x9876)
        assertEquals(n, r1.name)
        assertEquals(DnsRecordType.A, r1.type)
        assertEquals(DnsClass.HESIOD, r1.dclass)
        assertEquals(0x9876, r1.ttl)
        assertEquals((r as ARecord?)!!.address, (r1 as ARecord).address)
    }

    @Throws(TextParseException::class, UnknownHostException::class)
    fun test_setTTL() {
        val n = fromString("My.N.")
        val d = byteArrayOf(23, 12, 9, 129.toByte())
        val exp = InetAddress.getByName("23.12.9.129")
        val r = newRecord(n, DnsRecordType.A, DnsClass.IN, 0xABCDE9, d)
        assertEquals(0xABCDE9, r!!.ttl)
        r.ttl = 0x9876
        assertEquals(n, r.name)
        assertEquals(DnsRecordType.A, r.type)
        assertEquals(DnsClass.IN, r.dclass)
        assertEquals(0x9876, r.ttl)
        assertEquals(exp, (r as ARecord?)!!.address)
    }

    @Throws(TextParseException::class)
    fun test_compareTo() {
        val n = fromString("My.N.")
        val n2 = fromString("my.n.")
        var m = fromString("My.M.")
        val d = byteArrayOf(23, 12, 9, 129.toByte())
        val d2 = byteArrayOf(23, 12, 9, 128.toByte())
        var r1 = newRecord(n, DnsRecordType.A, DnsClass.IN, 0xABCDE9, d)
        var r2 = newRecord(n, DnsRecordType.A, DnsClass.IN, 0xABCDE9, d)
        assertEquals(0, r1!!.compareTo(r1))
        assertEquals(0, r1.compareTo(r2))
        assertEquals(0, r2!!.compareTo(r1))

        // name comparison should be canonical
        r2 = newRecord(n2, DnsRecordType.A, DnsClass.IN, 0xABCDE9, d)
        assertEquals(0, r1.compareTo(r2))
        assertEquals(0, r2!!.compareTo(r1))

        // different name
        r2 = newRecord(m, DnsRecordType.A, DnsClass.IN, 0xABCDE9, d)
        assertEquals(n.compareTo(m), r1.compareTo(r2))
        assertEquals(m.compareTo(n), r2!!.compareTo(r1))

        // different DnsClass
        r2 = newRecord(n, DnsRecordType.A, DnsClass.CHAOS, 0xABCDE9, d)
        assertEquals(DnsClass.IN - DnsClass.CHAOS, r1.compareTo(r2))
        assertEquals(DnsClass.CHAOS - DnsClass.IN, r2!!.compareTo(r1))

        // different DnsRecordType
        r2 = newRecord(n, DnsRecordType.NS, DnsClass.IN, 0xABCDE9, m.toWire())
        assertEquals(DnsRecordType.A - DnsRecordType.NS, r1.compareTo(r2))
        assertEquals(DnsRecordType.NS - DnsRecordType.A, r2!!.compareTo(r1))

        // different data (same length)
        r2 = newRecord(n, DnsRecordType.A, DnsClass.IN, 0xABCDE9, d2)
        assertEquals(1, r1.compareTo(r2))
        assertEquals(-1, r2!!.compareTo(r1))

        // different data (one a prefix of the other)
        m = fromString("My.N.L.")
        r1 = newRecord(n, DnsRecordType.NS, DnsClass.IN, 0xABCDE9, n.toWire())
        r2 = newRecord(n, DnsRecordType.NS, DnsClass.IN, 0xABCDE9, m.toWire())
        assertEquals(-1, r1!!.compareTo(r2))
        assertEquals(1, r2!!.compareTo(r1))
    }

    @Throws(TextParseException::class)
    fun test_getAdditionalName() {
        val n = fromString("My.N.")
        val r: DnsRecord = SubRecord(n, DnsRecordType.A, DnsClass.IN, 0xABCDE9)
        assertNull(r.additionalName)
    }

    fun test_checkU8() {
        try {
            checkU8("field", -1)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
        assertEquals(0, checkU8("field", 0))
        assertEquals(0x9D, checkU8("field", 0x9D))
        assertEquals(0xFF, checkU8("field", 0xFF))
        try {
            checkU8("field", 0x100)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
    }

    fun test_checkU16() {
        try {
            checkU16("field", -1)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
        assertEquals(0, checkU16("field", 0))
        assertEquals(0x9DA1, checkU16("field", 0x9DA1))
        assertEquals(0xFFFF, checkU16("field", 0xFFFF))
        try {
            checkU16("field", 0x10000)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
    }

    fun test_checkU32() {
        try {
            checkU32("field", -1)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
        assertEquals(0, checkU32("field", 0))
        assertEquals(0x9DA1F02DL, checkU32("field", 0x9DA1F02DL))
        assertEquals(0xFFFFFFFFL, checkU32("field", 0xFFFFFFFFL))
        try {
            checkU32("field", 0x100000000L)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
    }

    @Throws(TextParseException::class)
    fun test_checkName() {
        val n = fromString("My.N.")
        val m = fromString("My.m")
        assertEquals(n, checkName("field", n))
        try {
            checkName("field", m)
            fail("RelativeNameException not thrown")
        } catch (ignored: RelativeNameException) {
        }
    }
}
