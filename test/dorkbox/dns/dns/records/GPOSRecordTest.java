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
import dorkbox.dns.dns.exceptions.TextParseException;
import dorkbox.dns.dns.exceptions.WireParseException;
import dorkbox.dns.dns.utils.Tokenizer;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

@SuppressWarnings("deprecation")
public
class GPOSRecordTest extends TestCase {
    public
    void test_ctor_0arg() {
        GPOSRecord gr = new GPOSRecord();
        assertNull(gr.getName());
        assertEquals(0, gr.getType());
        assertEquals(0, gr.getDclass());
        assertEquals(0, gr.getTtl());
    }

    public
    void test_getObject() {
        GPOSRecord gr = new GPOSRecord();
        DnsRecord r = gr.getObject();
        assertTrue(r instanceof GPOSRecord);
    }

    public static
    class Test_Ctor_6arg_doubles extends TestCase {
        private Name m_n;
        private long m_ttl;
        private double m_lat, m_long, m_alt;

        @Override
        protected
        void setUp() throws TextParseException {
            m_n = Name.Companion.fromString("The.Name.");
            m_ttl = 0xABCDL;
            m_lat = -10.43;
            m_long = 76.12;
            m_alt = 100.101;
        }

        public
        void test_basic() throws TextParseException {
            GPOSRecord gr = new GPOSRecord(m_n, DnsClass.IN, m_ttl, m_long, m_lat, m_alt);
            assertEquals(m_n, gr.getName());
            assertEquals(DnsClass.IN, gr.getDclass());
            assertEquals(DnsRecordType.GPOS, gr.getType());
            assertEquals(m_ttl, gr.getTtl());
            assertEquals(m_long, gr.getLongitude());
            assertEquals(m_lat, gr.getLatitude());
            assertEquals(m_alt, gr.getAltitude());
            assertEquals(Double.toString(m_long), gr.getLongitudeString());
            assertEquals(Double.toString(m_lat), gr.getLatitudeString());
            assertEquals(Double.toString(m_alt), gr.getAltitudeString());
        }

        public
        void test_toosmall_longitude() throws TextParseException {
            try {
                new GPOSRecord(m_n, DnsClass.IN, m_ttl, -90.001, m_lat, m_alt);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException e) {
            }
        }

        public
        void test_toobig_longitude() throws TextParseException {
            try {
                new GPOSRecord(m_n, DnsClass.IN, m_ttl, 90.001, m_lat, m_alt);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException e) {
            }
        }

        public
        void test_toosmall_latitude() throws TextParseException {
            try {
                new GPOSRecord(m_n, DnsClass.IN, m_ttl, m_long, -180.001, m_alt);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException e) {
            }
        }

        public
        void test_toobig_latitude() throws TextParseException {
            try {
                new GPOSRecord(m_n, DnsClass.IN, m_ttl, m_long, 180.001, m_alt);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException e) {
            }
        }

        public
        void test_invalid_string() {
            try {
                new GPOSRecord(m_n, DnsClass.IN, m_ttl, Double.toString(m_long), "120.\\00ABC", Double.toString(m_alt));
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException e) {
            }
        }
    }


    public static
    class Test_Ctor_6arg_Strings extends TestCase {
        private Name m_n;
        private long m_ttl;
        private double m_lat, m_long, m_alt;

        public
        void test_basic() throws TextParseException {
            GPOSRecord gr = new GPOSRecord(m_n,
                                           DnsClass.IN,
                                           m_ttl, Double.toString(m_long), Double.toString(m_lat), Double.toString(m_alt));
            assertEquals(m_n, gr.getName());
            assertEquals(DnsClass.IN, gr.getDclass());
            assertEquals(DnsRecordType.GPOS, gr.getType());
            assertEquals(m_ttl, gr.getTtl());
            assertEquals(m_long, gr.getLongitude());
            assertEquals(m_lat, gr.getLatitude());
            assertEquals(m_alt, gr.getAltitude());
            assertEquals(Double.toString(m_long), gr.getLongitudeString());
            assertEquals(Double.toString(m_lat), gr.getLatitudeString());
            assertEquals(Double.toString(m_alt), gr.getAltitudeString());
        }

        public
        void test_toosmall_longitude() throws TextParseException {
            try {
                new GPOSRecord(m_n, DnsClass.IN, m_ttl, "-90.001", Double.toString(m_lat), Double.toString(m_alt));
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException e) {
            }
        }        @Override
        protected
        void setUp() throws TextParseException {
            m_n = Name.Companion.fromString("The.Name.");
            m_ttl = 0xABCDL;
            m_lat = -10.43;
            m_long = 76.12;
            m_alt = 100.101;
        }

        public
        void test_toobig_longitude() throws TextParseException {
            try {
                new GPOSRecord(m_n, DnsClass.IN, m_ttl, "90.001", Double.toString(m_lat), Double.toString(m_alt));
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException e) {
            }
        }

        public
        void test_toosmall_latitude() throws TextParseException {
            try {
                new GPOSRecord(m_n, DnsClass.IN, m_ttl, Double.toString(m_long), "-180.001", Double.toString(m_alt));
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException e) {
            }
        }

        public
        void test_toobig_latitude() throws TextParseException {
            try {
                new GPOSRecord(m_n, DnsClass.IN, m_ttl, Double.toString(m_long), "180.001", Double.toString(m_alt));
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException e) {
            }
        }




    }


    public static
    class Test_rrFromWire extends TestCase {
        public
        void test_basic() throws IOException {
            byte[] raw = new byte[] {5, '-', '8', '.', '1', '2', 6, '1', '2', '3', '.', '0', '7', 3, '0', '.', '0'};
            DnsInput in = new DnsInput(raw);

            GPOSRecord gr = new GPOSRecord();
            gr.rrFromWire(in);
            assertEquals(-8.12, gr.getLongitude());
            assertEquals(123.07, gr.getLatitude());
            assertEquals(0.0, gr.getAltitude());
        }

        public
        void test_longitude_toosmall() throws IOException {
            byte[] raw = new byte[] {5, '-', '9', '5', '.', '0', 6, '1', '2', '3', '.', '0', '7', 3, '0', '.', '0'};
            DnsInput in = new DnsInput(raw);

            GPOSRecord gr = new GPOSRecord();
            try {
                gr.rrFromWire(in);
                fail("WireParseException not thrown");
            } catch (WireParseException e) {
            }
        }

        public
        void test_longitude_toobig() throws IOException {
            byte[] raw = new byte[] {5, '1', '8', '5', '.', '0', 6, '1', '2', '3', '.', '0', '7', 3, '0', '.', '0'};
            DnsInput in = new DnsInput(raw);

            GPOSRecord gr = new GPOSRecord();
            try {
                gr.rrFromWire(in);
                fail("WireParseException not thrown");
            } catch (WireParseException e) {
            }
        }

        public
        void test_latitude_toosmall() throws IOException {
            byte[] raw = new byte[] {5, '-', '8', '5', '.', '0', 6, '-', '1', '9', '0', '.', '0', 3, '0', '.', '0'};
            DnsInput in = new DnsInput(raw);

            GPOSRecord gr = new GPOSRecord();
            try {
                gr.rrFromWire(in);
                fail("WireParseException not thrown");
            } catch (WireParseException e) {
            }
        }

        public
        void test_latitude_toobig() throws IOException {
            byte[] raw = new byte[] {5, '-', '8', '5', '.', '0', 6, '2', '1', '9', '0', '.', '0', 3, '0', '.', '0'};
            DnsInput in = new DnsInput(raw);

            GPOSRecord gr = new GPOSRecord();
            try {
                gr.rrFromWire(in);
                fail("WireParseException not thrown");
            } catch (WireParseException e) {
            }
        }
    }


    public static
    class Test_rdataFromString extends TestCase {
        public
        void test_basic() throws IOException {
            Tokenizer t = new Tokenizer("10.45 171.121212 1010787");

            GPOSRecord gr = new GPOSRecord();
            gr.rdataFromString(t, null);
            assertEquals(10.45, gr.getLongitude());
            assertEquals(171.121212, gr.getLatitude());
            assertEquals(1010787.0, gr.getAltitude());
        }

        public
        void test_longitude_toosmall() throws IOException {
            Tokenizer t = new Tokenizer("-100.390 171.121212 1010787");

            GPOSRecord gr = new GPOSRecord();
            try {
                gr.rdataFromString(t, null);
                fail("IOException not thrown");
            } catch (IOException e) {
            }
        }

        public
        void test_longitude_toobig() throws IOException {
            Tokenizer t = new Tokenizer("90.00001 171.121212 1010787");

            GPOSRecord gr = new GPOSRecord();
            try {
                gr.rdataFromString(t, null);
                fail("IOException not thrown");
            } catch (IOException e) {
            }
        }

        public
        void test_latitude_toosmall() throws IOException {
            Tokenizer t = new Tokenizer("0.0 -180.01 1010787");

            GPOSRecord gr = new GPOSRecord();
            try {
                gr.rdataFromString(t, null);
                fail("IOException not thrown");
            } catch (IOException e) {
            }
        }

        public
        void test_latitude_toobig() throws IOException {
            Tokenizer t = new Tokenizer("0.0 180.01 1010787");

            GPOSRecord gr = new GPOSRecord();
            try {
                gr.rdataFromString(t, null);
                fail("IOException not thrown");
            } catch (IOException e) {
            }
        }

        public
        void test_invalid_string() throws IOException {
            Tokenizer t = new Tokenizer("1.0 2.0 \\435");
            try {
                GPOSRecord gr = new GPOSRecord();
                gr.rdataFromString(t, null);
            } catch (TextParseException e) {
            }
        }
    }

    public
    void test_rrToString() throws TextParseException {
        String exp = "\"10.45\" \"171.121212\" \"1010787.0\"";

        GPOSRecord gr = new GPOSRecord(Name.Companion.fromString("The.Name."), DnsClass.IN, 0x123, 10.45, 171.121212, 1010787);

        StringBuilder sb = new StringBuilder();
        gr.rrToString(sb);
        assertEquals(exp, sb.toString());
    }

    public
    void test_rrToWire() throws TextParseException {
        GPOSRecord gr = new GPOSRecord(Name.Companion.fromString("The.Name."), DnsClass.IN, 0x123, -10.45, 120.0, 111.0);

        byte[] exp = new byte[] {6, '-', '1', '0', '.', '4', '5', 5, '1', '2', '0', '.', '0', 5, '1', '1', '1', '.', '0'};

        DnsOutput out = new DnsOutput();
        gr.rrToWire(out, null, true);

        byte[] bar = out.toByteArray();

        assertEquals(exp.length, bar.length);
        for (int i = 0; i < exp.length; ++i) {
            assertEquals("i=" + i, exp[i], bar[i]);
        }
    }

    public static
    Test suite() {
        TestSuite s = new TestSuite();
        s.addTestSuite(Test_Ctor_6arg_doubles.class);
        s.addTestSuite(Test_Ctor_6arg_Strings.class);
        s.addTestSuite(Test_rrFromWire.class);
        s.addTestSuite(Test_rdataFromString.class);
        s.addTestSuite(GPOSRecordTest.class);
        return s;
    }
}
