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

import dorkbox.dns.dns.exceptions.InvalidTTLException;
import dorkbox.dns.dns.records.TTL;
import junit.framework.TestCase;

public
class TTLTest extends TestCase {
    private final long S = 1;
    private final long M = 60 * S;
    private final long H = 60 * M;
    private final long D = 24 * H;
    private final long W = 7 * D;

    public
    void test_parseTTL() {
        assertEquals(9876, TTL.parseTTL("9876"));

        assertEquals(0, TTL.parseTTL("0S"));
        assertEquals(0, TTL.parseTTL("0M"));
        assertEquals(0, TTL.parseTTL("0H"));
        assertEquals(0, TTL.parseTTL("0D"));
        assertEquals(0, TTL.parseTTL("0W"));

        assertEquals(S, TTL.parseTTL("1s"));
        assertEquals(M, TTL.parseTTL("1m"));
        assertEquals(H, TTL.parseTTL("1h"));
        assertEquals(D, TTL.parseTTL("1d"));
        assertEquals(W, TTL.parseTTL("1w"));

        assertEquals(98 * S, TTL.parseTTL("98S"));
        assertEquals(76 * M, TTL.parseTTL("76M"));
        assertEquals(54 * H, TTL.parseTTL("54H"));
        assertEquals(32 * D, TTL.parseTTL("32D"));
        assertEquals(10 * W, TTL.parseTTL("10W"));

        assertEquals(98 * S + 11 * M + 1234 * H + 2 * D + W, TTL.parseTTL("98S11M1234H2D01W"));
    }

    public
    void test_parseTTL_invalid() {
        try {
            TTL.parseTTL(null);
            fail("NumberFormatException not throw");
        } catch (NumberFormatException ignored) {
        }

        try {
            TTL.parseTTL("");
            fail("NumberFormatException not throw");
        } catch (NumberFormatException ignored) {
        }

        try {
            TTL.parseTTL("S");
            fail("NumberFormatException not throw");
        } catch (NumberFormatException ignored) {
        }

        try {
            TTL.parseTTL("10S4B");
            fail("NumberFormatException not throw");
        } catch (NumberFormatException ignored) {
        }

        try {
            TTL.parseTTL("1S" + 0xFFFFFFFFL + "S");
            fail("NumberFormatException not throw");
        } catch (NumberFormatException ignored) {
        }

        try {
            TTL.parseTTL("" + 0x100000000L);
            fail("NumberFormatException not throw");
        } catch (NumberFormatException ignored) {
        }
    }

    public
    void test_format() {
        assertEquals("0S", TTL.format(0));
        assertEquals("1S", TTL.format(1));
        assertEquals("59S", TTL.format(59));
        assertEquals("1M", TTL.format(60));
        assertEquals("59M", TTL.format(59 * M));
        assertEquals("1M33S", TTL.format(M + 33));
        assertEquals("59M59S", TTL.format(59 * M + 59 * S));
        assertEquals("1H", TTL.format(H));
        assertEquals("10H1M21S", TTL.format(10 * H + M + 21));
        assertEquals("23H59M59S", TTL.format(23 * H + 59 * M + 59));
        assertEquals("1D", TTL.format(D));
        assertEquals("4D18H45M30S", TTL.format(4 * D + 18 * H + 45 * M + 30));
        assertEquals("6D23H59M59S", TTL.format(6 * D + 23 * H + 59 * M + 59));
        assertEquals("1W", TTL.format(W));
        assertEquals("10W4D1H21M29S", TTL.format(10 * W + 4 * D + H + 21 * M + 29));
        assertEquals("3550W5D3H14M7S", TTL.format(0x7FFFFFFFL));
    }

    public
    void test_format_invalid() {
        try {
            TTL.format(-1);
            fail("InvalidTTLException not thrown");
        } catch (InvalidTTLException ignored) {
        }

        try {
            TTL.format(0x100000000L);
            fail("InvalidTTLException not thrown");
        } catch (InvalidTTLException ignored) {
        }
    }
}
