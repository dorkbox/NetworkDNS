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
        assertEquals(9876, TTL.INSTANCE.parseTTL("9876"));

        assertEquals(0, TTL.INSTANCE.parseTTL("0S"));
        assertEquals(0, TTL.INSTANCE.parseTTL("0M"));
        assertEquals(0, TTL.INSTANCE.parseTTL("0H"));
        assertEquals(0, TTL.INSTANCE.parseTTL("0D"));
        assertEquals(0, TTL.INSTANCE.parseTTL("0W"));

        assertEquals(S, TTL.INSTANCE.parseTTL("1s"));
        assertEquals(M, TTL.INSTANCE.parseTTL("1m"));
        assertEquals(H, TTL.INSTANCE.parseTTL("1h"));
        assertEquals(D, TTL.INSTANCE.parseTTL("1d"));
        assertEquals(W, TTL.INSTANCE.parseTTL("1w"));

        assertEquals(98 * S, TTL.INSTANCE.parseTTL("98S"));
        assertEquals(76 * M, TTL.INSTANCE.parseTTL("76M"));
        assertEquals(54 * H, TTL.INSTANCE.parseTTL("54H"));
        assertEquals(32 * D, TTL.INSTANCE.parseTTL("32D"));
        assertEquals(10 * W, TTL.INSTANCE.parseTTL("10W"));

        assertEquals(98 * S + 11 * M + 1234 * H + 2 * D + W, TTL.INSTANCE.parseTTL("98S11M1234H2D01W"));
    }

    public
    void test_parseTTL_invalid() {
        try {
            TTL.INSTANCE.parseTTL(null);
            fail("NumberFormatException not throw");
        } catch (NumberFormatException ignored) {
        }

        try {
            TTL.INSTANCE.parseTTL("");
            fail("NumberFormatException not throw");
        } catch (NumberFormatException ignored) {
        }

        try {
            TTL.INSTANCE.parseTTL("S");
            fail("NumberFormatException not throw");
        } catch (NumberFormatException ignored) {
        }

        try {
            TTL.INSTANCE.parseTTL("10S4B");
            fail("NumberFormatException not throw");
        } catch (NumberFormatException ignored) {
        }

        try {
            TTL.INSTANCE.parseTTL("1S" + 0xFFFFFFFFL + "S");
            fail("NumberFormatException not throw");
        } catch (NumberFormatException ignored) {
        }

        try {
            TTL.INSTANCE.parseTTL("" + 0x100000000L);
            fail("NumberFormatException not throw");
        } catch (NumberFormatException ignored) {
        }
    }

    public
    void test_format() {
        assertEquals("0S", TTL.INSTANCE.format(0));
        assertEquals("1S", TTL.INSTANCE.format(1));
        assertEquals("59S", TTL.INSTANCE.format(59));
        assertEquals("1M", TTL.INSTANCE.format(60));
        assertEquals("59M", TTL.INSTANCE.format(59 * M));
        assertEquals("1M33S", TTL.INSTANCE.format(M + 33));
        assertEquals("59M59S", TTL.INSTANCE.format(59 * M + 59 * S));
        assertEquals("1H", TTL.INSTANCE.format(H));
        assertEquals("10H1M21S", TTL.INSTANCE.format(10 * H + M + 21));
        assertEquals("23H59M59S", TTL.INSTANCE.format(23 * H + 59 * M + 59));
        assertEquals("1D", TTL.INSTANCE.format(D));
        assertEquals("4D18H45M30S", TTL.INSTANCE.format(4 * D + 18 * H + 45 * M + 30));
        assertEquals("6D23H59M59S", TTL.INSTANCE.format(6 * D + 23 * H + 59 * M + 59));
        assertEquals("1W", TTL.INSTANCE.format(W));
        assertEquals("10W4D1H21M29S", TTL.INSTANCE.format(10 * W + 4 * D + H + 21 * M + 29));
        assertEquals("3550W5D3H14M7S", TTL.INSTANCE.format(0x7FFFFFFFL));
    }

    public
    void test_format_invalid() {
        try {
            TTL.INSTANCE.format(-1);
            fail("InvalidTTLException not thrown");
        } catch (InvalidTTLException ignored) {
        }

        try {
            TTL.INSTANCE.format(0x100000000L);
            fail("InvalidTTLException not thrown");
        } catch (InvalidTTLException ignored) {
        }
    }
}
