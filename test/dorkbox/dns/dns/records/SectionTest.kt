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

import dorkbox.dns.dns.constants.DnsSection
import dorkbox.dns.dns.constants.DnsSection.longString
import dorkbox.dns.dns.constants.DnsSection.string
import dorkbox.dns.dns.constants.DnsSection.updString
import dorkbox.dns.dns.constants.DnsSection.value
import junit.framework.TestCase

class SectionTest : TestCase() {
    fun test_string() {
        // a regular one
        assertEquals("au", string(DnsSection.AUTHORITY))
        try {
            string(-1)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }

        //  (max is 3)
        try {
            string(4)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
    }

    fun test_value() {
        // regular one
        assertEquals(DnsSection.ADDITIONAL, value("ad"))

        // something that unknown
        assertEquals(-1, value("THIS IS DEFINITELY UNKNOWN"))

        // empty string
        assertEquals(-1, value(""))
    }

    fun test_longString() {
        assertEquals("ADDITIONAL RECORDS", longString(DnsSection.ADDITIONAL))
        try {
            longString(-1)
        } catch (ignored: IllegalArgumentException) {
        }
        try {
            longString(4)
        } catch (ignored: IllegalArgumentException) {
        }
    }

    fun test_updString() {
        assertEquals("ZONE", updString(DnsSection.ZONE))
        try {
            longString(-1)
        } catch (ignored: IllegalArgumentException) {
        }
        try {
            longString(4)
        } catch (ignored: IllegalArgumentException) {
        }
    }
}
