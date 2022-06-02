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

import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsClass;
import dorkbox.dns.dns.constants.DnsRecordType;
import dorkbox.dns.dns.exceptions.TextParseException;
import junit.framework.TestCase;

public
class SingleCompressedNameBaseTest extends TestCase {
    private static
    class TestClass extends SingleCompressedNameBase {
        public
        TestClass() {}

        public
        TestClass(Name name, int type, int dclass, long ttl, Name singleName, String desc) {
            super(name, type, dclass, ttl, singleName, desc);
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

        Name n = Name.Companion.fromString("my.name.");
        Name sn = Name.Companion.fromString("my.single.name.");

        tc = new TestClass(n, DnsRecordType.A, DnsClass.IN, 100L, sn, "The Description");

        assertSame(n, tc.getName());
        assertEquals(DnsRecordType.A, tc.getType());
        assertEquals(DnsClass.IN, tc.getDclass());
        assertEquals(100L, tc.getTtl());
        assertSame(sn, tc.getSingleName());
    }

    public
    void test_rrToWire() throws IOException, TextParseException {
        Name n = Name.Companion.fromString("my.name.");
        Name sn = Name.Companion.fromString("My.Single.Name.");

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
