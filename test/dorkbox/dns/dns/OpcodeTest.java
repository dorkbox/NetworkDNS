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

import dorkbox.dns.dns.constants.DnsOpCode;
import junit.framework.TestCase;

public
class OpcodeTest extends TestCase {
    public
    void test_string() {
        // a regular one
        assertEquals("IQUERY", DnsOpCode.string(DnsOpCode.IQUERY));

        // one that doesn't exist
        assertTrue(DnsOpCode.string(6)
                            .startsWith("RESERVED"));

        try {
            DnsOpCode.string(-1);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }

        //  (max is 0xF)
        try {
            DnsOpCode.string(0x10);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    public
    void test_value() {
        // regular one
        assertEquals(DnsOpCode.STATUS, DnsOpCode.value("STATUS"));

        // one thats undefined but within range
        assertEquals(6, DnsOpCode.value("RESERVED6"));

        // one thats undefined but out of range
        assertEquals(-1, DnsOpCode.value("RESERVED" + 0x10));

        // something that unknown
        assertEquals(-1, DnsOpCode.value("THIS IS DEFINITELY UNKNOWN"));

        // empty string
        assertEquals(-1, DnsOpCode.value(""));
    }
}
