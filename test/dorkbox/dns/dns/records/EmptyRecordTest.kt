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
import dorkbox.dns.dns.utils.Tokenizer
import junit.framework.TestCase
import java.io.IOException
import java.net.UnknownHostException

class EmptyRecordTest : TestCase() {
    @Throws(UnknownHostException::class)
    fun test_ctor() {
        val ar = EmptyRecord()
        try {
            // name isn't initialized yet!
            assertNull(ar.name)
            fail("Name should not be initialized!")
        } catch (ignored: Exception) {
        }
        assertEquals(0, ar.type)
        assertEquals(0, ar.dclass)
        assertEquals(0, ar.ttl)
    }

    fun test_getObject() {
        val ar = EmptyRecord()
        val r = ar.dnsRecord
        assertTrue(r is EmptyRecord)
    }

    @Throws(IOException::class)
    fun test_rrFromWire() {
        val i = DnsInput(byteArrayOf(1, 2, 3, 4, 5))
        i.jump(3)
        val er = EmptyRecord()
        er.rrFromWire(i)
        assertEquals(3, i.readIndex())
        try {
            // name isn't initialized yet!
            assertNull(er.name)
            fail("Name should not be initialized!")
        } catch (ignored: Exception) {
        }
        assertEquals(0, er.type)
        assertEquals(0, er.dclass)
        assertEquals(0, er.ttl)
    }

    @Throws(IOException::class)
    fun test_rdataFromString() {
        val t = Tokenizer("these are the tokens")
        val er = EmptyRecord()
        er.rdataFromString(t, null)
        try {
            // name isn't initialized yet!
            assertNull(er.name)
            fail("Name should not be initialized!")
        } catch (ignored: Exception) {
        }
        assertEquals(0, er.type)
        assertEquals(0, er.dclass)
        assertEquals(0, er.ttl)
        assertEquals("these", t.getString())
    }

    fun test_rrToString() {
        val er = EmptyRecord()
        val sb = StringBuilder()
        er.rrToString(sb)
        assertEquals("", sb.toString())
    }

    fun test_rrToWire() {
        val er = EmptyRecord()
        val out = DnsOutput()
        er.rrToWire(out, null, true)
        assertEquals(0, out.toByteArray().size)
    }
}
