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

import dorkbox.dns.dns.constants.DnsOpCode
import dorkbox.dns.dns.constants.DnsOpCode.string
import dorkbox.dns.dns.constants.DnsOpCode.value
import junit.framework.TestCase

class OpcodeTest : TestCase() {
    fun test_string() {
        // a regular one
        assertEquals("IQUERY", string(DnsOpCode.IQUERY))

        // one that doesn't exist
        assertTrue(
            string(6).startsWith("RESERVED")
        )
        try {
            string(-1)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }

        //  (max is 0xF)
        try {
            string(0x10)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
    }

    fun test_value() {
        // regular one
        assertEquals(DnsOpCode.STATUS, value("STATUS"))

        // one thats undefined but within range
        assertEquals(6, value("RESERVED6"))

        // one thats undefined but out of range
        assertEquals(-1, value("RESERVED" + 0x10))

        // something that unknown
        assertEquals(-1, value("THIS IS DEFINITELY UNKNOWN"))

        // empty string
        assertEquals(-1, value(""))
    }
}
