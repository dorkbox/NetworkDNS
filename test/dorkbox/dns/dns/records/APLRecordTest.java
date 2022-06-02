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
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsClass;
import dorkbox.dns.dns.constants.DnsRecordType;
import dorkbox.dns.dns.exceptions.RelativeNameException;
import dorkbox.dns.dns.exceptions.TextParseException;
import dorkbox.dns.dns.exceptions.WireParseException;
import dorkbox.dns.dns.records.APLRecord.Element;
import dorkbox.dns.dns.utils.Address;
import dorkbox.dns.dns.utils.Tokenizer;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public
class APLRecordTest {
    public static
    class Test_Element_init extends TestCase {
        InetAddress m_addr4;
        InetAddress m_addr6;

        @Override
        protected
        void setUp() throws TextParseException, UnknownHostException {
            m_addr4 = InetAddress.getByName("193.160.232.5");
            m_addr6 = InetAddress.getByName("2001:db8:85a3:8d3:1319:8a2e:370:7334");
        }

        public
        void test_valid_IPv4() {
            Element el = new Element(true, m_addr4, 16);
            assertEquals(Address.IPv4, el.getFamily());
            assertEquals(true, el.getNegative());
            assertEquals(m_addr4, el.getAddress());
            assertEquals(16, el.getPrefixLength());
        }

        public
        void test_invalid_IPv4() {
            try {
                new Element(true, m_addr4, 33);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException e) {
            }
        }

        public
        void test_valid_IPv6() {
            Element el = new Element(false, m_addr6, 74);
            assertEquals(Address.IPv6, el.getFamily());
            assertEquals(false, el.getNegative());
            assertEquals(m_addr6, el.getAddress());
            assertEquals(74, el.getPrefixLength());
        }

        public
        void test_invalid_IPv6() {
            try {
                new Element(true, m_addr6, 129);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException e) {
            }
        }
    }


    public static
    class Test_init extends TestCase {
        Name m_an, m_rn;
        long m_ttl;
        ArrayList<Element> m_elements;
        InetAddress m_addr4;
        String m_addr4_string;
        byte[] m_addr4_bytes;
        InetAddress m_addr6;
        String m_addr6_string;
        byte[] m_addr6_bytes;

        public
        void test_0arg() throws UnknownHostException {
            APLRecord ar = new APLRecord();
            assertNull(ar.getName());
            assertEquals(0, ar.getType());
            assertEquals(0, ar.getDclass());
            assertEquals(0, ar.getTtl());
            assertNull(ar.getElements());
        }

        public
        void test_getObject() {
            APLRecord ar = new APLRecord();
            DnsRecord r = ar.getObject();
            assertTrue(r instanceof APLRecord);
        }        @Override
        protected
        void setUp() throws TextParseException, UnknownHostException {
            m_an = Name.Companion.fromString("My.Absolute.Name.");
            m_rn = Name.Companion.fromString("My.Relative.Name");
            m_ttl = 0x13579;
            m_addr4_string = "193.160.232.5";
            m_addr4 = InetAddress.getByName(m_addr4_string);
            m_addr4_bytes = m_addr4.getAddress();

            m_addr6_string = "2001:db8:85a3:8d3:1319:8a2e:370:7334";
            m_addr6 = InetAddress.getByName(m_addr6_string);
            m_addr6_bytes = m_addr6.getAddress();

            m_elements = new ArrayList<>(2);
            Element e = new Element(true, m_addr4, 12);
            m_elements.add(e);

            e = new Element(false, m_addr6, 64);
            m_elements.add(e);
        }

        public
        void test_4arg_basic() {
            APLRecord ar = new APLRecord(m_an, DnsClass.IN, m_ttl, m_elements);
            assertEquals(m_an, ar.getName());
            assertEquals(DnsRecordType.APL, ar.getType());
            assertEquals(DnsClass.IN, ar.getDclass());
            assertEquals(m_ttl, ar.getTtl());
            assertEquals(m_elements, ar.getElements());
        }

        public
        void test_4arg_empty_elements() {
            APLRecord ar = new APLRecord(m_an, DnsClass.IN, m_ttl, new ArrayList<Element>());
            assertEquals(new ArrayList<Element>(), ar.getElements());
        }

        public
        void test_4arg_relative_name() {
            try {
                new APLRecord(m_rn, DnsClass.IN, m_ttl, m_elements);
                fail("RelativeNameException not thrown");
            } catch (RelativeNameException ignored) {
            }
        }

        public
        void test_4arg_invalid_elements() {
            m_elements = new ArrayList<Element>();
            // this is on purpose!
            //noinspection unchecked
            ((List)m_elements).add(new Object());
            try {
                new APLRecord(m_an, DnsClass.IN, m_ttl, m_elements);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException e) {
            }
        }
    }


    public static
    class Test_rrFromWire extends TestCase {
        InetAddress m_addr4;
        byte[] m_addr4_bytes;
        InetAddress m_addr6;
        byte[] m_addr6_bytes;

        public
        void test_validIPv4() throws IOException {
            byte[] raw = new byte[] {0, 1, 8, (byte) 0x84, m_addr4_bytes[0], m_addr4_bytes[1], m_addr4_bytes[2], m_addr4_bytes[3]};

            DnsInput di = new DnsInput(raw);
            APLRecord ar = new APLRecord();
            ar.rrFromWire(di);

            ArrayList<Element> exp = new ArrayList<>();
            exp.add(new Element(true, m_addr4, 8));
            assertEquals(exp, ar.getElements());
        }

        public
        void test_validIPv4_short_address() throws IOException {
            byte[] raw = new byte[] {0, 1, 20, (byte) 0x83, m_addr4_bytes[0], m_addr4_bytes[1], m_addr4_bytes[2]};

            DnsInput di = new DnsInput(raw);
            APLRecord ar = new APLRecord();
            ar.rrFromWire(di);

            InetAddress a = InetAddress.getByName("193.160.232.0");

            ArrayList<Element> exp = new ArrayList<>();
            exp.add(new Element(true, a, 20));
            assertEquals(exp, ar.getElements());
        }

        @Override
        protected
        void setUp() throws TextParseException, UnknownHostException {
            m_addr4 = InetAddress.getByName("193.160.232.5");
            m_addr4_bytes = m_addr4.getAddress();

            m_addr6 = InetAddress.getByName("2001:db8:85a3:8d3:1319:8a2e:370:7334");
            m_addr6_bytes = m_addr6.getAddress();
        }

        public
        void test_invalid_IPv4_prefix() throws IOException {
            byte[] raw = new byte[] {0, 1, 33, (byte) 0x84, m_addr4_bytes[0], m_addr4_bytes[1], m_addr4_bytes[2], m_addr4_bytes[3]};

            DnsInput di = new DnsInput(raw);
            APLRecord ar = new APLRecord();
            try {
                ar.rrFromWire(di);
                fail("WireParseException not thrown");
            } catch (WireParseException ignored) {
            }
        }

        public
        void test_invalid_IPv4_length() throws IOException {
            byte[] raw = new byte[] {0, 1, 8, (byte) 0x85, m_addr4_bytes[0], m_addr4_bytes[1], m_addr4_bytes[2], m_addr4_bytes[3], 10};

            DnsInput di = new DnsInput(raw);
            APLRecord ar = new APLRecord();
            try {
                ar.rrFromWire(di);
                fail("WireParseException not thrown");
            } catch (WireParseException ignored) {
            }
        }

        public
        void test_multiple_validIPv4() throws IOException {
            byte[] raw = new byte[] {0, 1, 8, (byte) 0x84, m_addr4_bytes[0], m_addr4_bytes[1], m_addr4_bytes[2], m_addr4_bytes[3], 0, 1, 30,
                                     (byte) 0x4, m_addr4_bytes[0], m_addr4_bytes[1], m_addr4_bytes[2], m_addr4_bytes[3],};

            DnsInput di = new DnsInput(raw);
            APLRecord ar = new APLRecord();
            ar.rrFromWire(di);

            ArrayList<Element> exp = new ArrayList<>();
            exp.add(new Element(true, m_addr4, 8));
            exp.add(new Element(false, m_addr4, 30));
            assertEquals(exp, ar.getElements());
        }

        public
        void test_validIPv6() throws IOException {
            byte[] raw = new byte[] {0, 2, (byte) 115, (byte) 0x10, m_addr6_bytes[0], m_addr6_bytes[1], m_addr6_bytes[2], m_addr6_bytes[3],
                                     m_addr6_bytes[4], m_addr6_bytes[5], m_addr6_bytes[6], m_addr6_bytes[7], m_addr6_bytes[8],
                                     m_addr6_bytes[9], m_addr6_bytes[10], m_addr6_bytes[11], m_addr6_bytes[12], m_addr6_bytes[13],
                                     m_addr6_bytes[14], m_addr6_bytes[15]};

            DnsInput di = new DnsInput(raw);
            APLRecord ar = new APLRecord();
            ar.rrFromWire(di);

            ArrayList<Element> exp = new ArrayList<>();
            exp.add(new Element(false, m_addr6, 115));
            assertEquals(exp, ar.getElements());
        }

        public
        void test_valid_nonIP() throws IOException {
            byte[] raw = new byte[] {0, 3, (byte) 130, (byte) 0x85, 1, 2, 3, 4, 5};

            DnsInput di = new DnsInput(raw);
            APLRecord ar = new APLRecord();
            ar.rrFromWire(di);

            List<Element> l = ar.getElements();
            assertEquals(1, l.size());

            Element el = (Element) l.get(0);
            assertEquals(3, el.getFamily());
            assertEquals(true, el.getNegative());
            assertEquals(130, el.getPrefixLength());
            assertTrue(Arrays.equals(new byte[] {1, 2, 3, 4, 5}, (byte[]) el.getAddress()));
        }
    }


    public static
    class Test_rdataFromString extends TestCase {
        InetAddress m_addr4;
        String m_addr4_string;
        byte[] m_addr4_bytes;
        InetAddress m_addr6;
        String m_addr6_string;
        byte[] m_addr6_bytes;

        public
        void test_validIPv4() throws IOException {
            Tokenizer t = new Tokenizer("1:" + m_addr4_string + "/11\n");
            APLRecord ar = new APLRecord();
            ar.rdataFromString(t, null);

            ArrayList<Element> exp = new ArrayList<>();
            exp.add(new Element(false, m_addr4, 11));

            assertEquals(exp, ar.getElements());

            // make sure extra token is put back
            assertEquals(Tokenizer.EOL, t.get().getType());
        }

        public
        void test_valid_multi() throws IOException {
            Tokenizer t = new Tokenizer("1:" + m_addr4_string + "/11 !2:" + m_addr6_string + "/100");
            APLRecord ar = new APLRecord();
            ar.rdataFromString(t, null);

            ArrayList<Element> exp = new ArrayList<>();
            exp.add(new Element(false, m_addr4, 11));
            exp.add(new Element(true, m_addr6, 100));

            assertEquals(exp, ar.getElements());
        }

        @Override
        protected
        void setUp() throws TextParseException, UnknownHostException {
            m_addr4_string = "193.160.232.5";
            m_addr4 = InetAddress.getByName(m_addr4_string);
            m_addr4_bytes = m_addr4.getAddress();

            m_addr6_string = "2001:db8:85a3:8d3:1319:8a2e:370:7334";
            m_addr6 = InetAddress.getByName(m_addr6_string);
            m_addr6_bytes = m_addr6.getAddress();
        }

        public
        void test_validIPv6() throws IOException {
            Tokenizer t = new Tokenizer("!2:" + m_addr6_string + "/36\n");
            APLRecord ar = new APLRecord();
            ar.rdataFromString(t, null);

            ArrayList<Element> exp = new ArrayList<>();
            exp.add(new Element(true, m_addr6, 36));

            assertEquals(exp, ar.getElements());

            // make sure extra token is put back
            assertEquals(Tokenizer.EOL, t.get().getType());
        }

        public
        void test_no_colon() throws IOException {
            Tokenizer t = new Tokenizer("!1192.68.0.1/20");
            APLRecord ar = new APLRecord();
            try {
                ar.rdataFromString(t, null);
                fail("TextParseException not thrown");
            } catch (TextParseException ignored) {
            }
        }

        public
        void test_colon_and_slash_swapped() throws IOException {
            Tokenizer t = new Tokenizer("!1/192.68.0.1:20");
            APLRecord ar = new APLRecord();
            try {
                ar.rdataFromString(t, null);
                fail("TextParseException not thrown");
            } catch (TextParseException ignored) {
            }
        }

        public
        void test_no_slash() throws IOException {
            Tokenizer t = new Tokenizer("!1:192.68.0.1|20");
            APLRecord ar = new APLRecord();
            try {
                ar.rdataFromString(t, null);
                fail("TextParseException not thrown");
            } catch (TextParseException ignored) {
            }
        }

        public
        void test_empty_family() throws IOException {
            Tokenizer t = new Tokenizer("!:192.68.0.1/20");
            APLRecord ar = new APLRecord();
            try {
                ar.rdataFromString(t, null);
                fail("TextParseException not thrown");
            } catch (TextParseException ignored) {
            }
        }

        public
        void test_malformed_family() throws IOException {
            Tokenizer t = new Tokenizer("family:192.68.0.1/20");
            APLRecord ar = new APLRecord();
            try {
                ar.rdataFromString(t, null);
                fail("TextParseException not thrown");
            } catch (TextParseException ignored) {
            }
        }

        public
        void test_invalid_family() throws IOException {
            Tokenizer t = new Tokenizer("3:192.68.0.1/20");
            APLRecord ar = new APLRecord();
            try {
                ar.rdataFromString(t, null);
                fail("TextParseException not thrown");
            } catch (TextParseException ignored) {
            }
        }

        public
        void test_empty_prefix() throws IOException {
            Tokenizer t = new Tokenizer("1:192.68.0.1/");
            APLRecord ar = new APLRecord();
            try {
                ar.rdataFromString(t, null);
                fail("TextParseException not thrown");
            } catch (TextParseException ignored) {
            }
        }

        public
        void test_malformed_prefix() throws IOException {
            Tokenizer t = new Tokenizer("1:192.68.0.1/prefix");
            APLRecord ar = new APLRecord();
            try {
                ar.rdataFromString(t, null);
                fail("TextParseException not thrown");
            } catch (TextParseException ignored) {
            }
        }

        public
        void test_invalid_prefix() throws IOException {
            Tokenizer t = new Tokenizer("1:192.68.0.1/33");
            APLRecord ar = new APLRecord();
            try {
                ar.rdataFromString(t, null);
                fail("TextParseException not thrown");
            } catch (TextParseException ignored) {
            }
        }

        public
        void test_empty_address() throws IOException {
            Tokenizer t = new Tokenizer("1:/33");
            APLRecord ar = new APLRecord();
            try {
                ar.rdataFromString(t, null);
                fail("TextParseException not thrown");
            } catch (TextParseException ignored) {
            }
        }

        public
        void test_malformed_address() throws IOException {
            Tokenizer t = new Tokenizer("1:A.B.C.D/33");
            APLRecord ar = new APLRecord();
            try {
                ar.rdataFromString(t, null);
                fail("TextParseException not thrown");
            } catch (TextParseException ignored) {
            }
        }
    }


    public static
    class Test_rrToString extends TestCase {
        Name m_an, m_rn;
        long m_ttl;
        ArrayList<Element> m_elements;
        InetAddress m_addr4;
        String m_addr4_string;
        byte[] m_addr4_bytes;
        InetAddress m_addr6;
        String m_addr6_string;
        byte[] m_addr6_bytes;

        public
        void test() {
            APLRecord ar = new APLRecord(m_an, DnsClass.IN, m_ttl, m_elements);
            StringBuilder sb = new StringBuilder();
            ar.rrToString(sb);
            assertEquals("!1:" + m_addr4_string + "/12 2:" + m_addr6_string + "/64", sb.toString());
        }

        @Override
        protected
        void setUp() throws TextParseException, UnknownHostException {
            m_an = Name.Companion.fromString("My.Absolute.Name.");
            m_rn = Name.Companion.fromString("My.Relative.Name");
            m_ttl = 0x13579;
            m_addr4_string = "193.160.232.5";
            m_addr4 = InetAddress.getByName(m_addr4_string);
            m_addr4_bytes = m_addr4.getAddress();

            m_addr6_string = "2001:db8:85a3:8d3:1319:8a2e:370:7334";
            m_addr6 = InetAddress.getByName(m_addr6_string);
            m_addr6_bytes = m_addr6.getAddress();

            m_elements = new ArrayList<>(2);
            Element e = new Element(true, m_addr4, 12);
            m_elements.add(e);

            e = new Element(false, m_addr6, 64);
            m_elements.add(e);
        }


    }


    public static
    class Test_rrToWire extends TestCase {
        Name m_an, m_rn;
        long m_ttl;
        ArrayList<Element> m_elements;
        InetAddress m_addr4;
        String m_addr4_string;
        byte[] m_addr4_bytes;
        InetAddress m_addr6;
        String m_addr6_string;
        byte[] m_addr6_bytes;

        public
        void test_empty() {
            APLRecord ar = new APLRecord(m_an, DnsClass.IN, m_ttl, new ArrayList<>());
            DnsOutput dout = new DnsOutput();

            ar.rrToWire(dout, null, true);
            assertTrue(Arrays.equals(new byte[0], dout.toByteArray()));
        }

        public
        void test_basic() {
            APLRecord ar = new APLRecord(m_an, DnsClass.IN, m_ttl, m_elements);

            byte[] exp = new byte[] {0, 1, 12, (byte) 0x84, m_addr4_bytes[0], m_addr4_bytes[1], m_addr4_bytes[2], m_addr4_bytes[3], 0, 2,
                                     64, 0x10, m_addr6_bytes[0], m_addr6_bytes[1], m_addr6_bytes[2], m_addr6_bytes[3], m_addr6_bytes[4],
                                     m_addr6_bytes[5], m_addr6_bytes[6], m_addr6_bytes[7], m_addr6_bytes[8], m_addr6_bytes[9],
                                     m_addr6_bytes[10], m_addr6_bytes[11], m_addr6_bytes[12], m_addr6_bytes[13], m_addr6_bytes[14],
                                     m_addr6_bytes[15]};

            DnsOutput dout = new DnsOutput();

            ar.rrToWire(dout, null, true);
            assertTrue(Arrays.equals(exp, dout.toByteArray()));
        }

        @Override
        protected
        void setUp() throws TextParseException, UnknownHostException {
            m_an = Name.Companion.fromString("My.Absolute.Name.");
            m_rn = Name.Companion.fromString("My.Relative.Name");
            m_ttl = 0x13579;
            m_addr4_string = "193.160.232.5";
            m_addr4 = InetAddress.getByName(m_addr4_string);
            m_addr4_bytes = m_addr4.getAddress();

            m_addr6_string = "2001:db8:85a3:8d3:1319:8a2e:370:7334";
            m_addr6 = InetAddress.getByName(m_addr6_string);
            m_addr6_bytes = m_addr6.getAddress();

            m_elements = new ArrayList<>(2);
            Element e = new Element(true, m_addr4, 12);
            m_elements.add(e);

            e = new Element(false, m_addr6, 64);
            m_elements.add(e);
        }

        public
        void test_non_IP() throws IOException {
            byte[] exp = new byte[] {0, 3, (byte) 130, (byte) 0x85, 1, 2, 3, 4, 5};

            DnsInput di = new DnsInput(exp);
            APLRecord ar = new APLRecord();
            ar.rrFromWire(di);

            DnsOutput dout = new DnsOutput();

            ar.rrToWire(dout, null, true);
            assertTrue(Arrays.equals(exp, dout.toByteArray()));
        }

        public
        void test_address_with_embedded_zero() throws UnknownHostException {
            InetAddress a = InetAddress.getByName("232.0.11.1");
            ArrayList<Element> elements = new ArrayList<>();
            elements.add(new Element(true, a, 31));

            APLRecord ar = new APLRecord(m_an, DnsClass.IN, m_ttl, elements);

            byte[] exp = new byte[] {0, 1, 31, (byte) 0x84, (byte) 232, 0, 11, 1};

            DnsOutput dout = new DnsOutput();

            ar.rrToWire(dout, null, true);
            assertTrue(Arrays.equals(exp, dout.toByteArray()));
        }

        public
        void test_short_address() throws UnknownHostException {
            InetAddress a = InetAddress.getByName("232.0.11.0");
            ArrayList<Element> elements = new ArrayList<>();
            elements.add(new Element(true, a, 31));

            APLRecord ar = new APLRecord(m_an, DnsClass.IN, m_ttl, elements);

            byte[] exp = new byte[] {0, 1, 31, (byte) 0x83, (byte) 232, 0, 11};

            DnsOutput dout = new DnsOutput();

            ar.rrToWire(dout, null, true);
            assertTrue(Arrays.equals(exp, dout.toByteArray()));
        }

        public
        void test_wildcard_address() throws UnknownHostException {
            InetAddress a = InetAddress.getByName("0.0.0.0");
            ArrayList<Element> elements = new ArrayList<>();
            elements.add(new Element(true, a, 31));

            APLRecord ar = new APLRecord(m_an, DnsClass.IN, m_ttl, elements);

            byte[] exp = new byte[] {0, 1, 31, (byte) 0x80};

            DnsOutput dout = new DnsOutput();

            ar.rrToWire(dout, null, true);
            assertTrue(Arrays.equals(exp, dout.toByteArray()));
        }
    }

    public static
    Test suite() {
        TestSuite s = new TestSuite();
        s.addTestSuite(Test_Element_init.class);
        s.addTestSuite(Test_init.class);
        s.addTestSuite(Test_rrFromWire.class);
        s.addTestSuite(Test_rdataFromString.class);
        s.addTestSuite(Test_rrToString.class);
        s.addTestSuite(Test_rrToWire.class);
        return s;
    }
}
