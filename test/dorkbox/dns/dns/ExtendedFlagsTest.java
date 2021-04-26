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

import dorkbox.dns.dns.constants.ExtendedFlags;
import junit.framework.TestCase;

public
class ExtendedFlagsTest extends TestCase {
    public
    void test_string() {
        // a regular one
        assertEquals("do", ExtendedFlags.DO.string());

        // one that doesn't exist
        assertTrue(ExtendedFlags.string(1)
                                .startsWith("flag"));

        try {
            ExtendedFlags.string(-1);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }

        //  (max is 0xFFFF)
        try {
            ExtendedFlags.string(0x10000);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    public
    void test_value() {
        // regular one
        assertEquals(ExtendedFlags.DO.value(), ExtendedFlags.value("do"));

        // one thats undefined but within range
        assertEquals(16, ExtendedFlags.value("FLAG16"));

        // one thats undefined but out of range
        assertEquals(-1, ExtendedFlags.value("FLAG" + 0x10000));

        // something that unknown
        assertEquals(-1, ExtendedFlags.value("THIS IS DEFINITELY UNKNOWN"));

        // empty string
        assertEquals(-1, ExtendedFlags.value(""));
    }
}
