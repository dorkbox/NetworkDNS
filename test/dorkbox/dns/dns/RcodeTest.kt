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
package dorkbox.dns.dns

import dorkbox.dns.dns.constants.DnsResponseCode
import dorkbox.dns.dns.constants.DnsResponseCode.TSIGstring
import dorkbox.dns.dns.constants.DnsResponseCode.string
import dorkbox.dns.dns.constants.DnsResponseCode.value
import junit.framework.TestCase

class RcodeTest : TestCase() {
    fun test_string() {
        // a regular one
        assertEquals("NXDOMAIN", string(DnsResponseCode.NXDOMAIN))

        // one with an alias
        assertEquals("NOTIMP", string(DnsResponseCode.NOTIMP))

        // one that doesn't exist
        assertTrue(string(20).startsWith("RESERVED"))

        try {
            string(-1)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }

        //  (max is 0xFFF)
        try {
            string(0x1000)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
    }

    fun test_TSIGstring() {
        // a regular one
        assertEquals("BADSIG", TSIGstring(DnsResponseCode.BADSIG))

        // one that doesn't exist
        assertTrue(TSIGstring(22).startsWith("RESERVED"))

        try {
            TSIGstring(-1)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }

        //  (max is 0xFFFF)
        try {
            string(0x10000)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
    }

    fun test_value() {
        // regular one
        assertEquals(DnsResponseCode.FORMERR, value("FORMERR"))

        // one with alias
        assertEquals(DnsResponseCode.NOTIMP, value("NOTIMP"))
        assertEquals(DnsResponseCode.NOTIMP, value("NOTIMPL"))

        // one thats undefined but within range
        assertEquals(35, value("RESERVED35"))

        // one thats undefined but out of range
        assertEquals(-1, value("RESERVED" + 0x1000))

        // something that unknown
        assertEquals(-1, value("THIS IS DEFINITELY UNKNOWN"))

        // empty string
        assertEquals(-1, value(""))
    }
}
