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
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public
class DSRecordTest extends TestCase {
    public
    void test_ctor_0arg() {
        DSRecord dr = new DSRecord();
        assertNull(dr.getName());
        assertEquals(0, dr.getType());
        assertEquals(0, dr.getDClass());
        assertEquals(0, dr.getTTL());
        assertEquals(0, dr.getAlgorithm());
        assertEquals(0, dr.getDigestID());
        assertNull(dr.getDigest());
        assertEquals(0, dr.getFootprint());
    }

    public
    void test_getObject() {
        DSRecord dr = new DSRecord();
        DnsRecord r = dr.getObject();
        assertTrue(r instanceof DSRecord);
    }

    public static
    class Test_Ctor_7arg extends TestCase {
        private Name m_n;
        private long m_ttl;
        private int m_footprint;
        private int m_algorithm;
        private int m_digestid;
        private byte[] m_digest;

        @Override
        protected
        void setUp() throws TextParseException {
            m_n = Name.fromString("The.Name.");
            m_ttl = 0xABCDL;
            m_footprint = 0xEF01;
            m_algorithm = 0x23;
            m_digestid = 0x45;
            m_digest = new byte[] {(byte) 0x67, (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF};
        }

        public
        void test_basic() throws TextParseException {
            DSRecord dr = new DSRecord(m_n, DnsClass.IN, m_ttl, m_footprint, m_algorithm, m_digestid, m_digest);
            assertEquals(m_n, dr.getName());
            assertEquals(DnsClass.IN, dr.getDClass());
            assertEquals(DnsRecordType.DS, dr.getType());
            assertEquals(m_ttl, dr.getTTL());
            assertEquals(m_footprint, dr.getFootprint());
            assertEquals(m_algorithm, dr.getAlgorithm());
            assertEquals(m_digestid, dr.getDigestID());
            assertTrue(Arrays.equals(m_digest, dr.getDigest()));
        }

        public
        void test_toosmall_footprint() throws TextParseException {
            try {
                new DSRecord(m_n, DnsClass.IN, m_ttl, -1, m_algorithm, m_digestid, m_digest);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException e) {
            }
        }

        public
        void test_toobig_footprint() throws TextParseException {
            try {
                new DSRecord(m_n, DnsClass.IN, m_ttl, 0x10000, m_algorithm, m_digestid, m_digest);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException e) {
            }
        }

        public
        void test_toosmall_algorithm() throws TextParseException {
            try {
                new DSRecord(m_n, DnsClass.IN, m_ttl, m_footprint, -1, m_digestid, m_digest);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException e) {
            }
        }

        public
        void test_toobig_algorithm() throws TextParseException {
            try {
                new DSRecord(m_n, DnsClass.IN, m_ttl, m_footprint, 0x10000, m_digestid, m_digest);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException e) {
            }
        }

        public
        void test_toosmall_digestid() throws TextParseException {
            try {
                new DSRecord(m_n, DnsClass.IN, m_ttl, m_footprint, m_algorithm, -1, m_digest);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException e) {
            }
        }

        public
        void test_toobig_digestid() throws TextParseException {
            try {
                new DSRecord(m_n, DnsClass.IN, m_ttl, m_footprint, m_algorithm, 0x10000, m_digest);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException e) {
            }
        }

        public
        void test_null_digest() {
            DSRecord dr = new DSRecord(m_n, DnsClass.IN, m_ttl, m_footprint, m_algorithm, m_digestid, null);
            assertEquals(m_n, dr.getName());
            assertEquals(DnsClass.IN, dr.getDClass());
            assertEquals(DnsRecordType.DS, dr.getType());
            assertEquals(m_ttl, dr.getTTL());
            assertEquals(m_footprint, dr.getFootprint());
            assertEquals(m_algorithm, dr.getAlgorithm());
            assertEquals(m_digestid, dr.getDigestID());
            assertNull(dr.getDigest());
        }
    }

    public
    void test_rrFromWire() throws IOException {
        byte[] raw = new byte[] {(byte) 0xAB, (byte) 0xCD, (byte) 0xEF, (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89};
        DnsInput in = new DnsInput(raw);

        DSRecord dr = new DSRecord();
        dr.rrFromWire(in);
        assertEquals(0xABCD, dr.getFootprint());
        assertEquals(0xEF, dr.getAlgorithm());
        assertEquals(0x01, dr.getDigestID());
        assertTrue(Arrays.equals(new byte[] {(byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89}, dr.getDigest()));
    }

    public
    void test_rdataFromString() throws IOException {
        byte[] raw = new byte[] {(byte) 0xAB, (byte) 0xCD, (byte) 0xEF, (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89};
        Tokenizer t = new Tokenizer(0xABCD + " " + 0xEF + " " + 0x01 + " 23456789AB");

        DSRecord dr = new DSRecord();
        dr.rdataFromString(t, null);
        assertEquals(0xABCD, dr.getFootprint());
        assertEquals(0xEF, dr.getAlgorithm());
        assertEquals(0x01, dr.getDigestID());
        assertTrue(Arrays.equals(new byte[] {(byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89, (byte) 0xAB}, dr.getDigest()));
    }

    public
    void test_rrToString() throws TextParseException {
        String exp = 0xABCD + " " + 0xEF + " " + 0x01 + " 23456789AB";

        DSRecord dr = new DSRecord(Name.fromString("The.Name."),
                                   DnsClass.IN,
                                   0x123,
                                   0xABCD,
                                   0xEF,
                                   0x01,
                                   new byte[] {(byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89, (byte) 0xAB});

        StringBuilder sb = new StringBuilder();
        dr.rrToString(sb);
        assertEquals(exp, sb.toString());
    }

    public
    void test_rrToWire() throws TextParseException {
        DSRecord dr = new DSRecord(Name.fromString("The.Name."),
                                   DnsClass.IN,
                                   0x123,
                                   0xABCD,
                                   0xEF,
                                   0x01,
                                   new byte[] {(byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89, (byte) 0xAB});

        byte[] exp = new byte[] {(byte) 0xAB, (byte) 0xCD, (byte) 0xEF, (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89,
                                 (byte) 0xAB};

        DnsOutput out = new DnsOutput();
        dr.rrToWire(out, null, true);

        assertTrue(Arrays.equals(exp, out.toByteArray()));
    }

    public static
    Test suite() {
        TestSuite s = new TestSuite();
        s.addTestSuite(Test_Ctor_7arg.class);
        s.addTestSuite(DSRecordTest.class);
        return s;
    }
}
