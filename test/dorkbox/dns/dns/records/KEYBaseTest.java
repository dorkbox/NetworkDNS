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

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsClass;
import dorkbox.dns.dns.constants.DnsRecordType;
import dorkbox.dns.dns.exceptions.TextParseException;
import dorkbox.dns.dns.utils.Options;
import dorkbox.dns.dns.utils.Tokenizer;
import dorkbox.os.OS;
import junit.framework.TestCase;

public
class KEYBaseTest extends TestCase {
    private static
    class TestClass extends KEYBase {
        public
        TestClass() {}

        public
        TestClass(Name name, int type, int dclass, long ttl, int flags, int proto, int alg, byte[] key) {
            super(name, type, dclass, ttl, flags, proto, alg, key);
        }

        @Override
        public
        DnsRecord getObject() {
            return null;
        }

        @Override
        public
        void rdataFromString(@NotNull final Tokenizer st, @Nullable final Name origin) throws IOException {

        }
    }

    public
    void test_ctor() throws TextParseException {
        TestClass tc = new TestClass();
        assertEquals(0, tc.getFlags());
        assertEquals(0, tc.getProtocol());
        assertEquals(0, tc.getAlgorithm());
        assertNull(tc.getKey());

        Name n = Name.Companion.fromString("my.name.");
        byte[] key = new byte[] {0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};

        tc = new TestClass(n, DnsRecordType.KEY, DnsClass.IN, 100L, 0xFF, 0xF, 0xE, key);

        assertSame(n, tc.getName());
        assertEquals(DnsRecordType.KEY, tc.getType());
        assertEquals(DnsClass.IN, tc.getDclass());
        assertEquals(100L, tc.getTtl());
        assertEquals(0xFF, tc.getFlags());
        assertEquals(0xF, tc.getProtocol());
        assertEquals(0xE, tc.getAlgorithm());
        assertTrue(Arrays.equals(key, tc.getKey()));
    }

    public
    void test_rrFromWire() throws IOException {
        byte[] raw = new byte[] {(byte) 0xAB, (byte) 0xCD, (byte) 0xEF, (byte) 0x19, 1, 2, 3, 4, 5};
        DnsInput in = new DnsInput(raw);

        TestClass tc = new TestClass();
        tc.rrFromWire(in);

        assertEquals(0xABCD, tc.getFlags());
        assertEquals(0xEF, tc.getProtocol());
        assertEquals(0x19, tc.getAlgorithm());
        assertTrue(Arrays.equals(new byte[] {1, 2, 3, 4, 5}, tc.getKey()));


        raw = new byte[] {(byte) 0xBA, (byte) 0xDA, (byte) 0xFF, (byte) 0x28};
        in = new DnsInput(raw);

        tc = new TestClass();
        tc.rrFromWire(in);

        assertEquals(0xBADA, tc.getFlags());
        assertEquals(0xFF, tc.getProtocol());
        assertEquals(0x28, tc.getAlgorithm());
        assertNull(tc.getKey());
    }

    public
    void test_rrToString() throws IOException, TextParseException {
        Name n = Name.Companion.fromString("my.name.");
        byte[] key = new byte[] {0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};

        TestClass tc = new TestClass(n, DnsRecordType.KEY, DnsClass.IN, 100L, 0xFF, 0xF, 0xE, null);

        StringBuilder sb = new StringBuilder();
        tc.rrToString(sb);
        String out = sb.toString();

        assertEquals("255 15 14", out);

        tc = new TestClass(n, DnsRecordType.KEY, DnsClass.IN, 100L, 0xFF, 0xF, 0xE, key);

        sb = new StringBuilder();
        tc.rrToString(sb);
        out = sb.toString();

        assertEquals("255 15 14 " + Base64.getEncoder().encodeToString(key), out);


        Options.INSTANCE.set("multiline");

        sb = new StringBuilder();
        tc.rrToString(sb);
        out = sb.toString();

        assertEquals("255 15 14 (" + OS.INSTANCE.getLINE_SEPARATOR() + Base64.getMimeEncoder().encodeToString(key) + OS.INSTANCE.getLINE_SEPARATOR() + ") ; key_tag = 18509", out);

        Options.unset("multiline");
    }

    public
    void test_getFootprint() throws TextParseException {
        Name n = Name.Companion.fromString("my.name.");
        byte[] key = new byte[] {0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};

        TestClass tc = new TestClass(n, DnsRecordType.KEY, DnsClass.IN, 100L, 0xFF, 0xF, DNSSEC.Algorithm.RSAMD5, key);

        int foot = tc.getFootprint();
        // second-to-last and third-to-last bytes of key for RSAMD5
        assertEquals(0xD0E, foot);
        assertEquals(foot, tc.getFootprint());

        // key with an odd number of bytes
        tc = new TestClass(n, DnsRecordType.KEY, DnsClass.IN, 100L, 0x89AB, 0xCD, 0xEF, new byte[] {0x12, 0x34, 0x56});

        // rrToWire gives: { 0x89, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56 }
        // 89AB + CDEF + 1234 + 5600 = 1BCFE
        // 1BFCE + 1 = 1BFCF & FFFF = BFCF
        foot = tc.getFootprint();
        assertEquals(0xBFCF, foot);
        assertEquals(foot, tc.getFootprint());

        // empty
        tc = new TestClass();
        assertEquals(0, tc.getFootprint());
    }

    public
    void test_rrToWire() throws IOException, TextParseException {
        Name n = Name.Companion.fromString("my.name.");
        byte[] key = new byte[] {0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};

        TestClass tc = new TestClass(n, DnsRecordType.KEY, DnsClass.IN, 100L, 0x7689, 0xAB, 0xCD, key);

        byte[] exp = new byte[] {(byte) 0x76, (byte) 0x89, (byte) 0xAB, (byte) 0xCD, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

        DnsOutput o = new DnsOutput();

        // canonical
        tc.rrToWire(o, null, true);
        assertTrue(Arrays.equals(exp, o.toByteArray()));

        // not canonical
        o = new DnsOutput();
        tc.rrToWire(o, null, false);
        assertTrue(Arrays.equals(exp, o.toByteArray()));
    }
}
