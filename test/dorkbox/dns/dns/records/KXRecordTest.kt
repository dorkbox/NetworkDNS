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
import dorkbox.dns.dns.exceptions.TextParseException
import junit.framework.TestCase

class KXRecordTest : TestCase() {
    fun test_getObject() {
        val d = KXRecord()
        val r = d.dnsRecord
        assertTrue(r is KXRecord)
    }

    @Throws(TextParseException::class)
    fun test_ctor_5arg() {
        val n = fromString("My.Name.")
        val m = fromString("My.OtherName.")
        val d = KXRecord(n, DnsClass.IN, 0xABCDEL, 0xF1, m)
        assertEquals(n, d.name)
        assertEquals(DnsRecordType.KX, d.type)
        assertEquals(DnsClass.IN, d.dclass)
        assertEquals(0xABCDEL, d.ttl)
        assertEquals(0xF1, d.preference)
        assertEquals(m, d.target)
        assertEquals(m, d.additionalName)
    }
}
