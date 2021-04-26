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
package dorkbox.dns.dns;

import dorkbox.dns.dns.constants.DnsClass;
import junit.framework.TestCase;

public
class DClassTest extends TestCase {
    public
    void test_string() {
        // a regular one
        assertEquals("IN", DnsClass.string(DnsClass.IN));

        // one with an alias
        assertEquals("CH", DnsClass.string(DnsClass.CH));

        // one that doesn't exist
        assertTrue(DnsClass.string(20)
                           .startsWith("CLASS"));

        try {
            DnsClass.string(-1);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }

        //  (max is 0xFFFF)
        try {
            DnsClass.string(0x10000);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    public
    void test_value() {
        // regular one
        assertEquals(DnsClass.NONE, DnsClass.value("NONE"));

        // one with alias
        assertEquals(DnsClass.HS, DnsClass.value("HS"));
        assertEquals(DnsClass.HS, DnsClass.value("HESIOD"));

        // one thats undefined but within range
        assertEquals(21, DnsClass.value("CLASS21"));

        // something that unknown
        assertEquals(-1, DnsClass.value("THIS IS DEFINITELY UNKNOWN"));

        // empty string
        assertEquals(-1, DnsClass.value(""));
    }
}
