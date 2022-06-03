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

import dorkbox.dns.dns.constants.Flags
import dorkbox.dns.dns.constants.Flags.Companion.isFlag
import dorkbox.dns.dns.constants.Flags.Companion.toFlag
import junit.framework.TestCase

class FlagsTest : TestCase() {
    fun test_string() {
        // a regular one
        assertEquals("aa", Flags.AA.string())

        // one that doesn't exist
        try {
            toFlag(12)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
        try {
            toFlag(-1)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }

        //  (max is 0xF)
        try {
            toFlag(0x10)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
    }

    fun test_value() {
        // regular one
        assertEquals(Flags.CD, toFlag("cd"))

        // one that's undefined but within range
        try {
            toFlag("FLAG13")
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }

        // one that's undefined but out of range
        try {
            toFlag("FLAG" + 0x10)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }

        // something that's unknown
        try {
            toFlag("THIS IS DEFINITELY UNKNOWN")
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }

        // empty string
        try {
            toFlag("")
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
    }

    fun test_isFlag() {
        assertFalse(isFlag(-1)) // invalid
        assertTrue(isFlag(0))
        assertFalse(isFlag(1)) // opcode
        assertFalse(isFlag(2))
        assertFalse(isFlag(3))
        assertFalse(isFlag(4))
        assertTrue(isFlag(5))
        assertTrue(isFlag(6))
        assertTrue(isFlag(7))
        assertTrue(isFlag(8))
        assertTrue(isFlag(9))
        assertTrue(isFlag(10))
        assertTrue(isFlag(11))
        assertFalse(isFlag(12))
        assertFalse(isFlag(13))
        assertFalse(isFlag(14))
        assertFalse(isFlag(15))
        assertFalse(isFlag(16)) // invalid
    }
}
