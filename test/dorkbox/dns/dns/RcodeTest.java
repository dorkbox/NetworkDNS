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

import dorkbox.dns.dns.constants.DnsResponseCode;
import junit.framework.TestCase;

public
class RcodeTest extends TestCase {
    public
    void test_string() {
        // a regular one
        assertEquals("NXDOMAIN", DnsResponseCode.INSTANCE.string(DnsResponseCode.NXDOMAIN));

        // one with an alias
        assertEquals("NOTIMP", DnsResponseCode.INSTANCE.string(DnsResponseCode.NOTIMP));

        // one that doesn't exist
        assertTrue(DnsResponseCode.INSTANCE.string(20)
                                  .startsWith("RESERVED"));

        try {
            DnsResponseCode.INSTANCE.string(-1);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException ignored) {
        }

        //  (max is 0xFFF)
        try {
            DnsResponseCode.INSTANCE.string(0x1000);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException ignored) {
        }
    }

    public
    void test_TSIGstring() {
        // a regular one
        assertEquals("BADSIG", DnsResponseCode.INSTANCE.TSIGstring(DnsResponseCode.BADSIG));

        // one that doesn't exist
        assertTrue(DnsResponseCode.INSTANCE.TSIGstring(22)
                                  .startsWith("RESERVED"));

        try {
            DnsResponseCode.INSTANCE.TSIGstring(-1);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException ignored) {
        }

        //  (max is 0xFFFF)
        try {
            DnsResponseCode.INSTANCE.string(0x10000);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException ignored) {
        }
    }

    public
    void test_value() {
        // regular one
        assertEquals(DnsResponseCode.FORMERR, DnsResponseCode.INSTANCE.value("FORMERR"));

        // one with alias
        assertEquals(DnsResponseCode.NOTIMP, DnsResponseCode.INSTANCE.value("NOTIMP"));
        assertEquals(DnsResponseCode.NOTIMP, DnsResponseCode.INSTANCE.value("NOTIMPL"));

        // one thats undefined but within range
        assertEquals(35, DnsResponseCode.INSTANCE.value("RESERVED35"));

        // one thats undefined but out of range
        assertEquals(-1, DnsResponseCode.INSTANCE.value("RESERVED" + 0x1000));

        // something that unknown
        assertEquals(-1, DnsResponseCode.INSTANCE.value("THIS IS DEFINITELY UNKNOWN"));

        // empty string
        assertEquals(-1, DnsResponseCode.INSTANCE.value(""));
    }
}
