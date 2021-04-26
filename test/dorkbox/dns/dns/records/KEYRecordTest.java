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
import java.net.UnknownHostException;
import java.util.Arrays;

import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsClass;
import dorkbox.dns.dns.constants.DnsRecordType;
import dorkbox.dns.dns.exceptions.RelativeNameException;
import dorkbox.dns.dns.exceptions.TextParseException;
import dorkbox.dns.dns.records.DNSSEC;
import dorkbox.dns.dns.records.DnsRecord;
import dorkbox.dns.dns.records.KEYRecord;
import dorkbox.dns.dns.utils.Tokenizer;
import junit.framework.TestCase;

public
class KEYRecordTest extends TestCase {
    public
    void test_ctor_0arg() throws UnknownHostException {
        KEYRecord ar = new KEYRecord();
        assertNull(ar.getName());
        assertEquals(0, ar.getType());
        assertEquals(0, ar.getDClass());
        assertEquals(0, ar.getTTL());
        assertEquals(0, ar.getAlgorithm());
        assertEquals(0, ar.getFlags());
        assertEquals(0, ar.getFootprint());
        assertEquals(0, ar.getProtocol());
        assertNull(ar.getKey());
    }

    public
    void test_getObject() {
        KEYRecord ar = new KEYRecord();
        DnsRecord r = ar.getObject();
        assertTrue(r instanceof KEYRecord);
    }

    public
    void test_ctor_7arg() throws TextParseException {
        Name n = Name.fromString("My.Absolute.Name.");
        Name r = Name.fromString("My.Relative.Name");
        byte[] key = new byte[] {0, 1, 3, 5, 7, 9};

        KEYRecord kr = new KEYRecord(n, DnsClass.IN, 0x24AC, 0x9832, 0x12, 0x67, key);
        assertEquals(n, kr.getName());
        assertEquals(DnsRecordType.KEY, kr.getType());
        assertEquals(DnsClass.IN, kr.getDClass());
        assertEquals(0x24AC, kr.getTTL());
        assertEquals(0x9832, kr.getFlags());
        assertEquals(0x12, kr.getProtocol());
        assertEquals(0x67, kr.getAlgorithm());
        assertTrue(Arrays.equals(key, kr.getKey()));

        // a relative name
        try {
            new KEYRecord(r, DnsClass.IN, 0x24AC, 0x9832, 0x12, 0x67, key);
            fail("RelativeNameException not thrown");
        } catch (RelativeNameException e) {
        }
    }

    public
    void test_Protocol_string() {
        // a regular one
        assertEquals("DNSSEC", KEYRecord.Protocol.string(KEYRecord.Protocol.DNSSEC));
        // a unassigned value within range
        assertEquals("254", KEYRecord.Protocol.string(0xFE));
        // too low
        try {
            KEYRecord.Protocol.string(-1);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
        // too high
        try {
            KEYRecord.Protocol.string(0x100);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    public
    void test_Protocol_value() {
        // a regular one
        assertEquals(KEYRecord.Protocol.IPSEC, KEYRecord.Protocol.value("IPSEC"));
        // a unassigned value within range
        assertEquals(254, KEYRecord.Protocol.value("254"));
        // too low
        assertEquals(-1, KEYRecord.Protocol.value("-2"));
        // too high
        assertEquals(-1, KEYRecord.Protocol.value("256"));
    }

    public
    void test_Flags_value() {
        // numeric

        // lower bound
        assertEquals(-1, KEYRecord.Flags.value("-2"));
        assertEquals(0, KEYRecord.Flags.value("0"));
        // in the middle
        assertEquals(0xAB35, KEYRecord.Flags.value(0xAB35 + ""));
        // upper bound
        assertEquals(0xFFFF, KEYRecord.Flags.value(0xFFFF + ""));
        assertEquals(-1, KEYRecord.Flags.value(0x10000 + ""));

        // textual

        // single
        assertEquals(KEYRecord.Flags.EXTEND, KEYRecord.Flags.value("EXTEND"));
        // single invalid
        assertEquals(-1, KEYRecord.Flags.value("NOT_A_VALID_NAME"));
        // multiple
        assertEquals(KEYRecord.Flags.NOAUTH | KEYRecord.Flags.FLAG10 | KEYRecord.Flags.ZONE, KEYRecord.Flags.value("NOAUTH|ZONE|FLAG10"));
        // multiple invalid
        assertEquals(-1, KEYRecord.Flags.value("NOAUTH|INVALID_NAME|FLAG10"));
        // pathological
        assertEquals(0, KEYRecord.Flags.value("|"));
    }

    public
    void test_rdataFromString() throws IOException, TextParseException {
        // basic
        KEYRecord kr = new KEYRecord();
        Tokenizer st = new Tokenizer("NOAUTH|ZONE|FLAG10 EMAIL RSASHA1 AQIDBAUGBwgJ");
        kr.rdataFromString(st, null);
        assertEquals(KEYRecord.Flags.NOAUTH | KEYRecord.Flags.FLAG10 | KEYRecord.Flags.ZONE, kr.getFlags());
        assertEquals(KEYRecord.Protocol.EMAIL, kr.getProtocol());
        assertEquals(DNSSEC.Algorithm.RSASHA1, kr.getAlgorithm());
        assertTrue(Arrays.equals(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9}, kr.getKey()));

        // basic w/o key
        kr = new KEYRecord();
        st = new Tokenizer("NOAUTH|NOKEY|FLAG10 TLS 3");
        kr.rdataFromString(st, null);
        assertEquals(KEYRecord.Flags.NOAUTH | KEYRecord.Flags.FLAG10 | KEYRecord.Flags.NOKEY, kr.getFlags());
        assertEquals(KEYRecord.Protocol.TLS, kr.getProtocol());
        assertEquals(3, kr.getAlgorithm()); // Was ECC
        assertNull(kr.getKey());

        // invalid flags
        kr = new KEYRecord();
        st = new Tokenizer("NOAUTH|ZONE|JUNK EMAIL RSASHA1 AQIDBAUGBwgJ");
        try {
            kr.rdataFromString(st, null);
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }

        // invalid protocol
        kr = new KEYRecord();
        st = new Tokenizer("NOAUTH|ZONE RSASHA1 3 AQIDBAUGBwgJ");
        try {
            kr.rdataFromString(st, null);
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }

        // invalid algorithm
        kr = new KEYRecord();
        st = new Tokenizer("NOAUTH|ZONE EMAIL ZONE AQIDBAUGBwgJ");
        try {
            kr.rdataFromString(st, null);
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }
    }
}
