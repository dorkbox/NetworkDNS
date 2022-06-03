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

class NSRecordTest : TestCase() {
    fun test_ctor_0arg() {
        val d = NSRecord()
        try {
            // name isn't initialized yet!
            assertNull(d.name)
            assertNull(d.target)
            assertNull(d.additionalName)
            fail("Name should not be initialized!")
        } catch (ignored: Exception) {
        }
    }

    @Throws(TextParseException::class)
    fun test_ctor_4arg() {
        val n = fromString("my.name.")
        val a = fromString("my.alias.")
        val d = NSRecord(n, DnsClass.IN, 0xABCDEL, a)
        assertEquals(n, d.name)
        assertEquals(DnsRecordType.NS, d.type)
        assertEquals(DnsClass.IN, d.dclass)
        assertEquals(0xABCDEL, d.ttl)
        assertEquals(a, d.target)
        assertEquals(a, d.additionalName)
    }

    fun test_getObject() {
        val d = NSRecord()
        val r = d.`object`
        assertTrue(r is NSRecord)
    }
}
