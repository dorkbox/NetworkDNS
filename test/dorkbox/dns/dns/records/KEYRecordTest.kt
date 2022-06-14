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
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.exceptions.RelativeNameException
import dorkbox.dns.dns.exceptions.TextParseException
import dorkbox.dns.dns.records.KEYRecord.Flags.value
import dorkbox.dns.dns.records.KEYRecord.Protocol.string
import dorkbox.dns.dns.utils.Tokenizer
import junit.framework.TestCase
import java.io.IOException
import java.net.UnknownHostException
import java.util.*

class KEYRecordTest : TestCase() {
    @Throws(UnknownHostException::class)
    fun test_ctor_0arg() {
        val ar = KEYRecord()
        try {
            // name isn't initialized yet!
            assertNull(ar.name)
            fail("Name should not be initialized!")
        } catch (ignored: Exception) {
        }
        assertEquals(0, ar.type)
        assertEquals(0, ar.dclass)
        assertEquals(0, ar.ttl)
        assertEquals(0, ar.algorithm)
        assertEquals(0, ar.flags)
        assertEquals(0, ar.footprint)
        assertEquals(0, ar.protocol)
        assertNull(ar.key)
    }

    fun test_getObject() {
        val ar = KEYRecord()
        val r = ar.dnsRecord
        assertTrue(r is KEYRecord)
    }

    @Throws(TextParseException::class)
    fun test_ctor_7arg() {
        val n = fromString("My.Absolute.Name.")
        val r = fromString("My.Relative.Name")
        val key = byteArrayOf(0, 1, 3, 5, 7, 9)
        val kr = KEYRecord(n, DnsClass.IN, 0x24AC, 0x9832, 0x12, 0x67, key)
        assertEquals(n, kr.name)
        assertEquals(DnsRecordType.KEY, kr.type)
        assertEquals(DnsClass.IN, kr.dclass)
        assertEquals(0x24AC, kr.ttl)
        assertEquals(0x9832, kr.flags)
        assertEquals(0x12, kr.protocol)
        assertEquals(0x67, kr.algorithm)
        assertTrue(Arrays.equals(key, kr.key))

        // a relative name
        try {
            KEYRecord(r, DnsClass.IN, 0x24AC, 0x9832, 0x12, 0x67, key)
            fail("RelativeNameException not thrown")
        } catch (e: RelativeNameException) {
        }
    }

    fun test_Protocol_string() {
        // a regular one
        assertEquals("DNSSEC", string(KEYRecord.Protocol.DNSSEC))
        // a unassigned value within range
        assertEquals("254", string(0xFE))
        // too low
        try {
            string(-1)
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
        }
        // too high
        try {
            string(0x100)
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
        }
    }

    fun test_Protocol_value() {
        // a regular one
        assertEquals(KEYRecord.Protocol.IPSEC, KEYRecord.Protocol.value("IPSEC"))
        // a unassigned value within range
        assertEquals(254, KEYRecord.Protocol.value("254"))
        // too low
        assertEquals(-1, KEYRecord.Protocol.value("-2"))
        // too high
        assertEquals(-1, KEYRecord.Protocol.value("256"))
    }

    fun test_Flags_value() {
        // numeric

        // lower bound
        assertEquals(-1, value("-2"))
        assertEquals(0, value("0"))
        // in the middle
        assertEquals(0xAB35, value(0xAB35.toString() + ""))
        // upper bound
        assertEquals(0xFFFF, value(0xFFFF.toString() + ""))
        assertEquals(-1, value(0x10000.toString() + ""))

        // textual

        // single
        assertEquals(KEYRecord.Flags.EXTEND, value("EXTEND"))
        // single invalid
        assertEquals(-1, value("NOT_A_VALID_NAME"))
        // multiple
        assertEquals(KEYRecord.Flags.NOAUTH or KEYRecord.Flags.FLAG10 or KEYRecord.Flags.ZONE, value("NOAUTH|ZONE|FLAG10"))
        // multiple invalid
        assertEquals(-1, value("NOAUTH|INVALID_NAME|FLAG10"))
        // pathological
        assertEquals(0, value("|"))
    }

    @Throws(IOException::class, TextParseException::class)
    fun test_rdataFromString() {
        // basic
        var kr = KEYRecord()
        var st = Tokenizer("NOAUTH|ZONE|FLAG10 EMAIL RSASHA1 AQIDBAUGBwgJ")
        kr.rdataFromString(st, null)
        assertEquals(KEYRecord.Flags.NOAUTH or KEYRecord.Flags.FLAG10 or KEYRecord.Flags.ZONE, kr.flags)
        assertEquals(KEYRecord.Protocol.EMAIL, kr.protocol)
        assertEquals(DNSSEC.Algorithm.RSASHA1, kr.algorithm)
        assertTrue(Arrays.equals(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9), kr.key))

        // basic w/o key
        kr = KEYRecord()
        st = Tokenizer("NOAUTH|NOKEY|FLAG10 TLS 3")
        kr.rdataFromString(st, null)
        assertEquals(KEYRecord.Flags.NOAUTH or KEYRecord.Flags.FLAG10 or KEYRecord.Flags.NOKEY, kr.flags)
        assertEquals(KEYRecord.Protocol.TLS, kr.protocol)
        assertEquals(3, kr.algorithm) // Was ECC
        assertNull(kr.key)

        // invalid flags
        kr = KEYRecord()
        st = Tokenizer("NOAUTH|ZONE|JUNK EMAIL RSASHA1 AQIDBAUGBwgJ")
        try {
            kr.rdataFromString(st, null)
            fail("TextParseException not thrown")
        } catch (e: TextParseException) {
        }

        // invalid protocol
        kr = KEYRecord()
        st = Tokenizer("NOAUTH|ZONE RSASHA1 3 AQIDBAUGBwgJ")
        try {
            kr.rdataFromString(st, null)
            fail("TextParseException not thrown")
        } catch (e: TextParseException) {
        }

        // invalid algorithm
        kr = KEYRecord()
        st = Tokenizer("NOAUTH|ZONE EMAIL ZONE AQIDBAUGBwgJ")
        try {
            kr.rdataFromString(st, null)
            fail("TextParseException not thrown")
        } catch (e: TextParseException) {
        }
    }
}
