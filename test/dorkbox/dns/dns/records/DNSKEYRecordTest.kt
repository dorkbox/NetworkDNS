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
import dorkbox.dns.dns.utils.Tokenizer
import junit.framework.TestCase
import java.io.IOException
import java.net.UnknownHostException
import java.util.*

class DNSKEYRecordTest : TestCase() {
    @Throws(UnknownHostException::class)
    fun test_ctor_0arg() {
        val ar = DNSKEYRecord()
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
        val ar = DNSKEYRecord()
        val r = ar.`object`
        assertTrue(r is DNSKEYRecord)
    }

    @Throws(TextParseException::class)
    fun test_ctor_7arg() {
        val n = fromString("My.Absolute.Name.")
        val r = fromString("My.Relative.Name")
        val key = byteArrayOf(0, 1, 3, 5, 7, 9)
        val kr = DNSKEYRecord(n, DnsClass.IN, 0x24AC, 0x9832, 0x12, 0x67, key)
        assertEquals(n, kr.name)
        assertEquals(DnsRecordType.DNSKEY, kr.type)
        assertEquals(DnsClass.IN, kr.dclass)
        assertEquals(0x24AC, kr.ttl)
        assertEquals(0x9832, kr.flags)
        assertEquals(0x12, kr.protocol)
        assertEquals(0x67, kr.algorithm)
        assertTrue(Arrays.equals(key, kr.key))

        // a relative name
        try {
            DNSKEYRecord(r, DnsClass.IN, 0x24AC, 0x9832, 0x12, 0x67, key)
            fail("RelativeNameException not thrown")
        } catch (e: RelativeNameException) {
        }
    }

    @Throws(IOException::class, TextParseException::class)
    fun test_rdataFromString() {
        // basic
        var kr = DNSKEYRecord()
        var st = Tokenizer(0xABCD.toString() + " " + 0x81 + " RSASHA1 AQIDBAUGBwgJ")
        kr.rdataFromString(st, null)
        assertEquals(0xABCD, kr.flags)
        assertEquals(0x81, kr.protocol)
        assertEquals(DNSSEC.Algorithm.RSASHA1, kr.algorithm)
        assertTrue(Arrays.equals(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9), kr.key))

        // invalid algorithm
        kr = DNSKEYRecord()
        st = Tokenizer(0x1212.toString() + " " + 0xAA + " ZONE AQIDBAUGBwgJ")
        try {
            kr.rdataFromString(st, null)
            fail("TextParseException not thrown")
        } catch (e: TextParseException) {
        }
    }
}
