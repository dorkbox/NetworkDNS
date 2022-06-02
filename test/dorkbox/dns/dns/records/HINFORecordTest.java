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
class HINFORecordTest extends TestCase {
    public
    void test_ctor_0arg() {
        HINFORecord dr = new HINFORecord();
        assertNull(dr.getName());
        assertEquals(0, dr.getType());
        assertEquals(0, dr.getDclass());
        assertEquals(0, dr.getTtl());
    }

    public
    void test_getObject() {
        HINFORecord dr = new HINFORecord();
        DnsRecord r = dr.getObject();
        assertTrue(r instanceof HINFORecord);
    }

    public
    void test_ctor_5arg() throws TextParseException {
        Name n = Name.Companion.fromString("The.Name.");
        long ttl = 0xABCDL;
        String cpu = "i686 Intel(R) Pentium(R) M processor 1.70GHz GenuineIntel GNU/Linux";
        String os = "Linux troy 2.6.10-gentoo-r6 #8 Wed Apr 6 21:25:04 MDT 2005";

        HINFORecord dr = new HINFORecord(n, DnsClass.IN, ttl, cpu, os);
        assertEquals(n, dr.getName());
        assertEquals(DnsClass.IN, dr.getDclass());
        assertEquals(DnsRecordType.HINFO, dr.getType());
        assertEquals(ttl, dr.getTtl());
        assertEquals(cpu, dr.getCPU());
        assertEquals(os, dr.getOS());
    }

    public
    void test_ctor_5arg_invalid_CPU() throws TextParseException {
        Name n = Name.Companion.fromString("The.Name.");
        long ttl = 0xABCDL;
        String cpu = "i686 Intel(R) Pentium(R) M \\256 processor 1.70GHz GenuineIntel GNU/Linux";
        String os = "Linux troy 2.6.10-gentoo-r6 #8 Wed Apr 6 21:25:04 MDT 2005";

        try {
            new HINFORecord(n, DnsClass.IN, ttl, cpu, os);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    public
    void test_ctor_5arg_invalid_OS() throws TextParseException {
        Name n = Name.Companion.fromString("The.Name.");
        long ttl = 0xABCDL;
        String cpu = "i686 Intel(R) Pentium(R) M processor 1.70GHz GenuineIntel GNU/Linux";
        String os = "Linux troy 2.6.10-gentoo-r6 \\1 #8 Wed Apr 6 21:25:04 MDT 2005";

        try {
            new HINFORecord(n, DnsClass.IN, ttl, cpu, os);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    public
    void test_rrFromWire() throws IOException {
        String cpu = "Intel(R) Pentium(R) M processor 1.70GHz";
        String os = "Linux troy 2.6.10-gentoo-r6";

        byte[] raw = new byte[] {39, 'I', 'n', 't', 'e', 'l', '(', 'R', ')', ' ', 'P', 'e', 'n', 't', 'i', 'u', 'm', '(', 'R', ')', ' ',
                                 'M', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', 'o', 'r', ' ', '1', '.', '7', '0', 'G', 'H', 'z', 27, 'L',
                                 'i', 'n', 'u', 'x', ' ', 't', 'r', 'o', 'y', ' ', '2', '.', '6', '.', '1', '0', '-', 'g', 'e', 'n', 't',
                                 'o', 'o', '-', 'r', '6'};

        DnsInput in = new DnsInput(raw);

        HINFORecord dr = new HINFORecord();
        dr.rrFromWire(in);
        assertEquals(cpu, dr.getCPU());
        assertEquals(os, dr.getOS());
    }

    public
    void test_rdataFromString() throws IOException {
        String cpu = "Intel(R) Pentium(R) M processor 1.70GHz";
        String os = "Linux troy 2.6.10-gentoo-r6";

        Tokenizer t = new Tokenizer("\"" + cpu + "\" \"" + os + "\"");

        HINFORecord dr = new HINFORecord();
        dr.rdataFromString(t, null);
        assertEquals(cpu, dr.getCPU());
        assertEquals(os, dr.getOS());
    }

    public
    void test_rdataFromString_invalid_CPU() throws IOException {
        String cpu = "Intel(R) Pentium(R) \\388 M processor 1.70GHz";
        String os = "Linux troy 2.6.10-gentoo-r6";

        Tokenizer t = new Tokenizer("\"" + cpu + "\" \"" + os + "\"");

        HINFORecord dr = new HINFORecord();
        try {
            dr.rdataFromString(t, null);
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }
    }

    public
    void test_rdataFromString_invalid_OS() throws IOException {
        String cpu = "Intel(R) Pentium(R) M processor 1.70GHz";

        Tokenizer t = new Tokenizer("\"" + cpu + "\"");

        HINFORecord dr = new HINFORecord();
        try {
            dr.rdataFromString(t, null);
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }
    }

    public
    void test_rrToString() throws TextParseException {
        String cpu = "Intel(R) Pentium(R) M processor 1.70GHz";
        String os = "Linux troy 2.6.10-gentoo-r6";

        String exp = "\"" + cpu + "\" \"" + os + "\"";

        HINFORecord dr = new HINFORecord(Name.Companion.fromString("The.Name."), DnsClass.IN, 0x123, cpu, os);
        StringBuilder sb = new StringBuilder();
        dr.rrToString(sb);
        assertEquals(exp, sb.toString());
    }

    public
    void test_rrToWire() throws TextParseException {
        String cpu = "Intel(R) Pentium(R) M processor 1.70GHz";
        String os = "Linux troy 2.6.10-gentoo-r6";
        byte[] raw = new byte[] {39, 'I', 'n', 't', 'e', 'l', '(', 'R', ')', ' ', 'P', 'e', 'n', 't', 'i', 'u', 'm', '(', 'R', ')', ' ',
                                 'M', ' ', 'p', 'r', 'o', 'c', 'e', 's', 's', 'o', 'r', ' ', '1', '.', '7', '0', 'G', 'H', 'z', 27, 'L',
                                 'i', 'n', 'u', 'x', ' ', 't', 'r', 'o', 'y', ' ', '2', '.', '6', '.', '1', '0', '-', 'g', 'e', 'n', 't',
                                 'o', 'o', '-', 'r', '6'};

        HINFORecord dr = new HINFORecord(Name.Companion.fromString("The.Name."), DnsClass.IN, 0x123, cpu, os);

        DnsOutput out = new DnsOutput();
        dr.rrToWire(out, null, true);

        assertTrue(Arrays.equals(raw, out.toByteArray()));
    }
}
