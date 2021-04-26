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
package dorkbox.dns.dns.records;

import dorkbox.dns.dns.constants.DnsSection;
import junit.framework.TestCase;

public
class SectionTest extends TestCase {
    public
    void test_string() {
        // a regular one
        assertEquals("au", DnsSection.string(DnsSection.AUTHORITY));

        try {
            DnsSection.string(-1);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }

        //  (max is 3)
        try {
            DnsSection.string(4);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    public
    void test_value() {
        // regular one
        assertEquals(DnsSection.ADDITIONAL, DnsSection.value("ad"));

        // something that unknown
        assertEquals(-1, DnsSection.value("THIS IS DEFINITELY UNKNOWN"));

        // empty string
        assertEquals(-1, DnsSection.value(""));
    }

    public
    void test_longString() {
        assertEquals("ADDITIONAL RECORDS", DnsSection.longString(DnsSection.ADDITIONAL));

        try {
            DnsSection.longString(-1);
        } catch (IllegalArgumentException e) {
        }
        try {
            DnsSection.longString(4);
        } catch (IllegalArgumentException e) {
        }
    }

    public
    void test_updString() {
        assertEquals("ZONE", DnsSection.updString(DnsSection.ZONE));

        try {
            DnsSection.longString(-1);
        } catch (IllegalArgumentException e) {
        }
        try {
            DnsSection.longString(4);
        } catch (IllegalArgumentException e) {
        }
    }
}
