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
import dorkbox.dns.dns.exceptions.TextParseException;
import dorkbox.dns.dns.utils.Tokenizer;
import junit.framework.TestCase;

public
class URIRecordTest extends TestCase {
    public
    void test_ctor_0arg() {
        URIRecord r = new URIRecord();
        assertNull(r.getName());
        assertEquals(0, r.getType());
        assertEquals(0, r.getDclass());
        assertEquals(0, r.getTtl());
        assertEquals(0, r.getPriority());
        assertEquals(0, r.getWeight());
        assertTrue("".equals(r.getTarget()));
    }

    public
    void test_getObject() {
        URIRecord dr = new URIRecord();
        DnsRecord r = dr.getObject();
        assertTrue(r instanceof URIRecord);
    }

    public
    void test_ctor_6arg() throws TextParseException {
        Name n = Name.Companion.fromString("my.name.");
        String target = ("http://foo");

        URIRecord r = new URIRecord(n, DnsClass.IN, 0xABCDEL, 42, 69, target);
        assertEquals(n, r.getName());
        assertEquals(DnsRecordType.URI, r.getType());
        assertEquals(DnsClass.IN, r.getDclass());
        assertEquals(0xABCDEL, r.getTtl());
        assertEquals(42, r.getPriority());
        assertEquals(69, r.getWeight());
        assertEquals(target, r.getTarget());
    }

    public
    void test_rdataFromString() throws IOException {
        Tokenizer t = new Tokenizer(0xABCD + " " + 0xEF01 + " " + "\"http://foo:1234/bar?baz=bum\"");

        URIRecord r = new URIRecord();
        r.rdataFromString(t, null);
        assertEquals(0xABCD, r.getPriority());
        assertEquals(0xEF01, r.getWeight());
        assertEquals("http://foo:1234/bar?baz=bum", r.getTarget());
    }

    public
    void test_rdataToWire() throws TextParseException {
        Name n = Name.Companion.fromString("my.name.");
        String target = ("http://foo");
        byte[] exp = new byte[] {(byte) 0xbe, (byte) 0xef, (byte) 0xde, (byte) 0xad, (byte) 0x68, (byte) 0x74, (byte) 0x74, (byte) 0x70,
                                 (byte) 0x3a, (byte) 0x2f, (byte) 0x2f, (byte) 0x66, (byte) 0x6f, (byte) 0x6f};

        URIRecord r = new URIRecord(n, DnsClass.IN, 0xABCDEL, 0xbeef, 0xdead, target);
        DnsOutput out = new DnsOutput();
        r.rrToWire(out, null, true);
        assertTrue(Arrays.equals(exp, out.toByteArray()));
    }

    public
    void test_rrFromWire() throws IOException {
        byte[] raw = new byte[] {(byte) 0xbe, (byte) 0xef, (byte) 0xde, (byte) 0xad, (byte) 0x68, (byte) 0x74, (byte) 0x74, (byte) 0x70,
                                 (byte) 0x3a, (byte) 0x2f, (byte) 0x2f, (byte) 0x66, (byte) 0x6f, (byte) 0x6f};
        DnsInput in = new DnsInput(raw);

        URIRecord r = new URIRecord();
        r.rrFromWire(in);
        assertEquals(0xBEEF, r.getPriority());
        assertEquals(0xDEAD, r.getWeight());
        assertEquals("http://foo", r.getTarget());
    }

    public
    void test_toobig_priority() throws TextParseException {
        try {
            new URIRecord(Name.Companion.fromString("the.name"), DnsClass.IN, 0x1234, 0x10000, 42, "http://foo");
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    public
    void test_toosmall_priority() throws TextParseException {
        try {
            new URIRecord(Name.Companion.fromString("the.name"), DnsClass.IN, 0x1234, -1, 42, "http://foo");
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    public
    void test_toobig_weight() throws TextParseException {
        try {
            new URIRecord(Name.Companion.fromString("the.name"), DnsClass.IN, 0x1234, 42, 0x10000, "http://foo");
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    public
    void test_toosmall_weight() throws TextParseException {
        try {
            new URIRecord(Name.Companion.fromString("the.name"), DnsClass.IN, 0x1234, 42, -1, "http://foo");
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

}
