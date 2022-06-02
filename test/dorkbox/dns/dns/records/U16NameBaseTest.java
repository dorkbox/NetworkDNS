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

import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsClass;
import dorkbox.dns.dns.constants.DnsRecordType;
import dorkbox.dns.dns.exceptions.RelativeNameException;
import dorkbox.dns.dns.exceptions.TextParseException;
import dorkbox.dns.dns.utils.Tokenizer;
import junit.framework.TestCase;

public
class U16NameBaseTest extends TestCase {
    private
    void assertEquals(byte[] exp, byte[] act) {
        assertTrue(java.util.Arrays.equals(exp, act));
    }

    private static
    class TestClass extends U16NameBase {
        public
        TestClass() {}

        public
        TestClass(Name name, int type, int dclass, long ttl) {
            super(name, type, dclass, ttl);
        }

        public
        TestClass(Name name, int type, int dclass, long ttl, int u16Field, String u16Description, Name nameField, String nameDescription) {
            super(name, type, dclass, ttl, u16Field, u16Description, nameField, nameDescription);
        }

        @Override
        public
        DnsRecord getObject() {
            return null;
        }
    }

    public
    void test_ctor_0arg() {
        TestClass tc = new TestClass();
        assertNull(tc.getName());
        assertEquals(0, tc.getType());
        assertEquals(0, tc.getDclass());
        assertEquals(0, tc.getTtl());
        assertEquals(0, tc.getU16Field());
        assertNull(tc.getNameField());
    }

    public
    void test_ctor_4arg() throws TextParseException {
        Name n = Name.Companion.fromString("My.Name.");

        TestClass tc = new TestClass(n, DnsRecordType.MX, DnsClass.IN, 0xBCDA);

        assertSame(n, tc.getName());
        assertEquals(DnsRecordType.MX, tc.getType());
        assertEquals(DnsClass.IN, tc.getDclass());
        assertEquals(0xBCDA, tc.getTtl());
        assertEquals(0, tc.getU16Field());
        assertNull(tc.getNameField());
    }

    public
    void test_ctor_8arg() throws TextParseException {
        Name n = Name.Companion.fromString("My.Name.");
        Name m = Name.Companion.fromString("My.Other.Name.");

        TestClass tc = new TestClass(n, DnsRecordType.MX, DnsClass.IN, 0xB12FL, 0x1F2B, "u16 description", m, "name description");

        assertSame(n, tc.getName());
        assertEquals(DnsRecordType.MX, tc.getType());
        assertEquals(DnsClass.IN, tc.getDclass());
        assertEquals(0xB12FL, tc.getTtl());
        assertEquals(0x1F2B, tc.getU16Field());
        assertEquals(m, tc.getNameField());

        // an invalid u16 value
        try {
            new TestClass(n, DnsRecordType.MX, DnsClass.IN, 0xB12FL, 0x10000, "u16 description", m, "name description");
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }

        // a relative name
        Name rel = Name.Companion.fromString("My.relative.Name");
        try {
            new TestClass(n, DnsRecordType.MX, DnsClass.IN, 0xB12FL, 0x1F2B, "u16 description", rel, "name description");
            fail("RelativeNameException not thrown");
        } catch (RelativeNameException e) {
        }

    }

    public
    void test_rrFromWire() throws IOException {
        byte[] raw = new byte[] {(byte) 0xBC, (byte) 0x1F, 2, 'M', 'y', 6, 's', 'i', 'N', 'g', 'l', 'E', 4, 'n', 'A', 'm', 'E', 0};
        DnsInput in = new DnsInput(raw);

        TestClass tc = new TestClass();
        tc.rrFromWire(in);

        Name exp = Name.Companion.fromString("My.single.name.");
        assertEquals(0xBC1FL, tc.getU16Field());
        assertEquals(exp, tc.getNameField());
    }

    public
    void test_rdataFromString() throws IOException {
        Name exp = Name.Companion.fromString("My.Single.Name.");

        Tokenizer t = new Tokenizer(0x19A2 + " My.Single.Name.");
        TestClass tc = new TestClass();
        tc.rdataFromString(t, null);

        assertEquals(0x19A2, tc.getU16Field());
        assertEquals(exp, tc.getNameField());

        t = new Tokenizer("10 My.Relative.Name");
        tc = new TestClass();
        try {
            tc.rdataFromString(t, null);
            fail("RelativeNameException not thrown");
        } catch (RelativeNameException e) {
        }
    }

    public
    void test_rrToString() throws IOException, TextParseException {
        Name n = Name.Companion.fromString("My.Name.");
        Name m = Name.Companion.fromString("My.Other.Name.");

        TestClass tc = new TestClass(n, DnsRecordType.MX, DnsClass.IN, 0xB12FL, 0x1F2B, "u16 description", m, "name description");

        StringBuilder sb = new StringBuilder();
        tc.rrToString(sb);
        String out = sb.toString();
        String exp = 0x1F2B + " My.Other.Name.";

        assertEquals(exp, out);
    }

    public
    void test_rrToWire() throws IOException, TextParseException {
        Name n = Name.Companion.fromString("My.Name.");
        Name m = Name.Companion.fromString("M.O.n.");

        TestClass tc = new TestClass(n, DnsRecordType.MX, DnsClass.IN, 0xB12FL, 0x1F2B, "u16 description", m, "name description");

        // canonical
        DnsOutput dout = new DnsOutput();
        tc.rrToWire(dout, null, true);
        byte[] out = dout.toByteArray();
        byte[] exp = new byte[] {0x1F, 0x2B, 1, 'm', 1, 'o', 1, 'n', 0};
        assertTrue(Arrays.equals(exp, out));

        // case sensitive
        dout = new DnsOutput();
        tc.rrToWire(dout, null, false);
        out = dout.toByteArray();
        exp = new byte[] {0x1F, 0x2B, 1, 'M', 1, 'O', 1, 'n', 0};
        assertTrue(Arrays.equals(exp, out));
    }
}
