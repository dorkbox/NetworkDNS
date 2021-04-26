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

import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsClass;
import dorkbox.dns.dns.constants.DnsRecordType;
import dorkbox.dns.dns.exceptions.RelativeNameException;
import dorkbox.dns.dns.exceptions.TextParseException;
import dorkbox.dns.dns.records.DnsRecord;
import dorkbox.dns.dns.records.SingleNameBase;
import dorkbox.dns.dns.utils.Tokenizer;
import junit.framework.TestCase;

public
class SingleNameBaseTest extends TestCase {
    private static
    class TestClass extends SingleNameBase {
        public
        TestClass() {}

        public
        TestClass(Name name, int type, int dclass, long ttl) {
            super(name, type, dclass, ttl);
        }

        public
        TestClass(Name name, int type, int dclass, long ttl, Name singleName, String desc) {
            super(name, type, dclass, ttl, singleName, desc);
        }

        @Override
        public
        Name getSingleName() {
            return super.getSingleName();
        }

        @Override
        public
        DnsRecord getObject() {
            return null;
        }
    }

    public
    void test_ctor() throws TextParseException {
        TestClass tc = new TestClass();
        assertNull(tc.getSingleName());

        Name n = Name.fromString("my.name.");
        Name sn = Name.fromString("my.single.name.");

        tc = new TestClass(n, DnsRecordType.A, DnsClass.IN, 100L);

        assertSame(n, tc.getName());
        assertEquals(DnsRecordType.A, tc.getType());
        assertEquals(DnsClass.IN, tc.getDClass());
        assertEquals(100L, tc.getTTL());

        tc = new TestClass(n, DnsRecordType.A, DnsClass.IN, 100L, sn, "The Description");

        assertSame(n, tc.getName());
        assertEquals(DnsRecordType.A, tc.getType());
        assertEquals(DnsClass.IN, tc.getDClass());
        assertEquals(100L, tc.getTTL());
        assertSame(sn, tc.getSingleName());
    }

    public
    void test_rrFromWire() throws IOException {
        byte[] raw = new byte[] {2, 'm', 'y', 6, 's', 'i', 'n', 'g', 'l', 'e', 4, 'n', 'a', 'm', 'e', 0};
        DnsInput in = new DnsInput(raw);

        TestClass tc = new TestClass();
        tc.rrFromWire(in);

        Name exp = Name.fromString("my.single.name.");
        assertEquals(exp, tc.getSingleName());
    }

    public
    void test_rdataFromString() throws IOException {
        Name exp = Name.fromString("my.single.name.");

        Tokenizer t = new Tokenizer("my.single.name.");
        TestClass tc = new TestClass();
        tc.rdataFromString(t, null);
        assertEquals(exp, tc.getSingleName());

        t = new Tokenizer("my.relative.name");
        tc = new TestClass();
        try {
            tc.rdataFromString(t, null);
            fail("RelativeNameException not thrown");
        } catch (RelativeNameException e) {
        }
    }

    public
    void test_rrToString() throws IOException, TextParseException {
        Name exp = Name.fromString("my.single.name.");

        Tokenizer t = new Tokenizer("my.single.name.");
        TestClass tc = new TestClass();
        tc.rdataFromString(t, null);
        assertEquals(exp, tc.getSingleName());

        StringBuilder sb = new StringBuilder();
        tc.rrToString(sb);
        String out = sb.toString();
        assertEquals(out, exp.toString());
    }

    public
    void test_rrToWire() throws IOException, TextParseException {
        Name n = Name.fromString("my.name.");
        Name sn = Name.fromString("My.Single.Name.");

        // non-canonical (case sensitive)
        TestClass tc = new TestClass(n, DnsRecordType.A, DnsClass.IN, 100L, sn, "The Description");
        byte[] exp = new byte[] {2, 'M', 'y', 6, 'S', 'i', 'n', 'g', 'l', 'e', 4, 'N', 'a', 'm', 'e', 0};

        DnsOutput dout = new DnsOutput();
        tc.rrToWire(dout, null, false);

        byte[] out = dout.toByteArray();
        assertEquals(exp, out);

        // canonical (lowercase)
        tc = new TestClass(n, DnsRecordType.A, DnsClass.IN, 100L, sn, "The Description");
        exp = new byte[] {2, 'm', 'y', 6, 's', 'i', 'n', 'g', 'l', 'e', 4, 'n', 'a', 'm', 'e', 0};

        dout = new DnsOutput();
        tc.rrToWire(dout, null, true);

        out = dout.toByteArray();
        assertEquals(exp, out);
    }

    private
    void assertEquals(byte[] exp, byte[] act) {
        assertTrue(java.util.Arrays.equals(exp, act));
    }
}
