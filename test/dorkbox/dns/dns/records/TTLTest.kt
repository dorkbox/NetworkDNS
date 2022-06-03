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

import dorkbox.dns.dns.exceptions.InvalidTTLException
import dorkbox.dns.dns.records.TTL.format
import dorkbox.dns.dns.records.TTL.parseTTL
import junit.framework.TestCase

class TTLTest : TestCase() {
    private val S: Long = 1
    private val M = 60 * S
    private val H = 60 * M
    private val D = 24 * H
    private val W = 7 * D

    fun test_parseTTL() {
        assertEquals(9876, parseTTL("9876"))
        assertEquals(0, parseTTL("0S"))
        assertEquals(0, parseTTL("0M"))
        assertEquals(0, parseTTL("0H"))
        assertEquals(0, parseTTL("0D"))
        assertEquals(0, parseTTL("0W"))
        assertEquals(S, parseTTL("1s"))
        assertEquals(M, parseTTL("1m"))
        assertEquals(H, parseTTL("1h"))
        assertEquals(D, parseTTL("1d"))
        assertEquals(W, parseTTL("1w"))
        assertEquals(98 * S, parseTTL("98S"))
        assertEquals(76 * M, parseTTL("76M"))
        assertEquals(54 * H, parseTTL("54H"))
        assertEquals(32 * D, parseTTL("32D"))
        assertEquals(10 * W, parseTTL("10W"))
        assertEquals(98 * S + 11 * M + 1234 * H + 2 * D + W, parseTTL("98S11M1234H2D01W"))
    }

    fun test_parseTTL_invalid() {
        try {
            parseTTL(null)
            fail("NumberFormatException not throw")
        } catch (ignored: NumberFormatException) {
        }
        try {
            parseTTL("")
            fail("NumberFormatException not throw")
        } catch (ignored: NumberFormatException) {
        }
        try {
            parseTTL("S")
            fail("NumberFormatException not throw")
        } catch (ignored: NumberFormatException) {
        }
        try {
            parseTTL("10S4B")
            fail("NumberFormatException not throw")
        } catch (ignored: NumberFormatException) {
        }
        try {
            parseTTL("1S" + 0xFFFFFFFFL + "S")
            fail("NumberFormatException not throw")
        } catch (ignored: NumberFormatException) {
        }
        try {
            parseTTL("" + 0x100000000L)
            fail("NumberFormatException not throw")
        } catch (ignored: NumberFormatException) {
        }
    }

    fun test_format() {
        assertEquals("0S", format(0))
        assertEquals("1S", format(1))
        assertEquals("59S", format(59))
        assertEquals("1M", format(60))
        assertEquals("59M", format(59 * M))
        assertEquals("1M33S", format(M + 33))
        assertEquals("59M59S", format(59 * M + 59 * S))
        assertEquals("1H", format(H))
        assertEquals("10H1M21S", format(10 * H + M + 21))
        assertEquals("23H59M59S", format(23 * H + 59 * M + 59))
        assertEquals("1D", format(D))
        assertEquals("4D18H45M30S", format(4 * D + 18 * H + 45 * M + 30))
        assertEquals("6D23H59M59S", format(6 * D + 23 * H + 59 * M + 59))
        assertEquals("1W", format(W))
        assertEquals("10W4D1H21M29S", format(10 * W + 4 * D + H + 21 * M + 29))
        assertEquals("3550W5D3H14M7S", format(0x7FFFFFFFL))
    }

    fun test_format_invalid() {
        try {
            format(-1)
            fail("InvalidTTLException not thrown")
        } catch (ignored: InvalidTTLException) {
        }
        try {
            format(0x100000000L)
            fail("InvalidTTLException not thrown")
        } catch (ignored: InvalidTTLException) {
        }
    }
}
