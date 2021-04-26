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
import dorkbox.dns.dns.records.DNSKEYRecord;
import dorkbox.dns.dns.records.DNSSEC;
import dorkbox.dns.dns.records.DnsRecord;
import dorkbox.dns.dns.utils.Tokenizer;
import junit.framework.TestCase;

public
class DNSKEYRecordTest extends TestCase {
    public
    void test_ctor_0arg() throws UnknownHostException {
        DNSKEYRecord ar = new DNSKEYRecord();
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
        DNSKEYRecord ar = new DNSKEYRecord();
        DnsRecord r = ar.getObject();
        assertTrue(r instanceof DNSKEYRecord);
    }

    public
    void test_ctor_7arg() throws TextParseException {
        Name n = Name.fromString("My.Absolute.Name.");
        Name r = Name.fromString("My.Relative.Name");
        byte[] key = new byte[] {0, 1, 3, 5, 7, 9};

        DNSKEYRecord kr = new DNSKEYRecord(n, DnsClass.IN, 0x24AC, 0x9832, 0x12, 0x67, key);
        assertEquals(n, kr.getName());
        assertEquals(DnsRecordType.DNSKEY, kr.getType());
        assertEquals(DnsClass.IN, kr.getDClass());
        assertEquals(0x24AC, kr.getTTL());
        assertEquals(0x9832, kr.getFlags());
        assertEquals(0x12, kr.getProtocol());
        assertEquals(0x67, kr.getAlgorithm());
        assertTrue(Arrays.equals(key, kr.getKey()));

        // a relative name
        try {
            new DNSKEYRecord(r, DnsClass.IN, 0x24AC, 0x9832, 0x12, 0x67, key);
            fail("RelativeNameException not thrown");
        } catch (RelativeNameException e) {
        }
    }

    public
    void test_rdataFromString() throws IOException, TextParseException {
        // basic
        DNSKEYRecord kr = new DNSKEYRecord();
        Tokenizer st = new Tokenizer(0xABCD + " " + 0x81 + " RSASHA1 AQIDBAUGBwgJ");
        kr.rdataFromString(st, null);
        assertEquals(0xABCD, kr.getFlags());
        assertEquals(0x81, kr.getProtocol());
        assertEquals(DNSSEC.Algorithm.RSASHA1, kr.getAlgorithm());
        assertTrue(Arrays.equals(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9}, kr.getKey()));

        // invalid algorithm
        kr = new DNSKEYRecord();
        st = new Tokenizer(0x1212 + " " + 0xAA + " ZONE AQIDBAUGBwgJ");
        try {
            kr.rdataFromString(st, null);
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }
    }
}
