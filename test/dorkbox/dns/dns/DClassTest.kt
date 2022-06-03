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

import dorkbox.dns.dns.constants.DnsClass
import dorkbox.dns.dns.constants.DnsClass.string
import dorkbox.dns.dns.constants.DnsClass.value
import junit.framework.TestCase

class DClassTest : TestCase() {
    fun test_string() {
        // a regular one
        assertEquals("IN", string(DnsClass.IN))

        // one with an alias
        assertEquals("CH", string(DnsClass.CH))

        // one that doesn't exist
        assertTrue(
            string(20).startsWith("CLASS")
        )

        try {
            string(-1)
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
        assertEquals(DnsClass.NONE, value("NONE"))

        // one with alias
        assertEquals(DnsClass.HS, value("HS"))
        assertEquals(DnsClass.HS, value("HESIOD"))

        // one thats undefined but within range
        assertEquals(21, value("CLASS21"))

        // something that unknown
        assertEquals(-1, value("THIS IS DEFINITELY UNKNOWN"))

        // empty string
        assertEquals(-1, value(""))
    }
}
