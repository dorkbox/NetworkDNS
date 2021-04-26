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

import dorkbox.dns.dns.constants.Flags;
import junit.framework.TestCase;

public
class FlagsTest extends TestCase {
    public
    void test_string() {
        // a regular one
        assertEquals("aa", Flags.AA.string());

        // one that doesn't exist
        try {
            Flags.toFlag(12);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException ignored) {
        }

        try {
            Flags.toFlag(-1);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException ignored) {
        }

        //  (max is 0xF)
        try {
            Flags.toFlag(0x10);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException ignored) {
        }
    }

    public
    void test_value() {
        // regular one
        assertEquals(Flags.CD, Flags.toFlag("cd"));

        // one that's undefined but within range
        try {
            Flags.toFlag("FLAG13");
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException ignored) {
        }

        // one that's undefined but out of range
        try {
            Flags.toFlag("FLAG" + 0x10);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException ignored) {
        }

        // something that's unknown
        try {
            Flags.toFlag("THIS IS DEFINITELY UNKNOWN");
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException ignored) {
        }

        // empty string
        try {
            Flags.toFlag("");
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException ignored) {
        }
    }

    public
    void test_isFlag() {
        assertFalse(Flags.isFlag(-1)); // invalid

        assertTrue(Flags.isFlag(0));
        assertFalse(Flags.isFlag(1)); // opcode
        assertFalse(Flags.isFlag(2));
        assertFalse(Flags.isFlag(3));
        assertFalse(Flags.isFlag(4));
        assertTrue(Flags.isFlag(5));
        assertTrue(Flags.isFlag(6));
        assertTrue(Flags.isFlag(7));
        assertTrue(Flags.isFlag(8));
        assertTrue(Flags.isFlag(9));
        assertTrue(Flags.isFlag(10));
        assertTrue(Flags.isFlag(11));
        assertFalse(Flags.isFlag(12));
        assertFalse(Flags.isFlag(13));
        assertFalse(Flags.isFlag(14));
        assertFalse(Flags.isFlag(15));

        assertFalse(Flags.isFlag(16)); // invalid
    }
}
