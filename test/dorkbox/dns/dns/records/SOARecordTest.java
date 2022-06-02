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
import java.util.Random;

import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsClass;
import dorkbox.dns.dns.constants.DnsRecordType;
import dorkbox.dns.dns.exceptions.RelativeNameException;
import dorkbox.dns.dns.exceptions.TextParseException;
import dorkbox.dns.dns.utils.Options;
import dorkbox.dns.dns.utils.Tokenizer;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public
class SOARecordTest {
    private final static Random m_random = new Random();

    private static
    long randomU16() {
        return m_random.nextLong() >>> 48;
    }

    private static
    long randomU32() {
        return m_random.nextLong() >>> 32;
    }

    public static
    class Test_init extends TestCase {
        private Name m_an, m_rn, m_host, m_admin;
        private long m_ttl, m_serial, m_refresh, m_retry, m_expire, m_minimum;

        @Override
        protected
        void setUp() throws TextParseException, UnknownHostException {
            m_an = Name.Companion.fromString("My.Absolute.Name.");
            m_rn = Name.Companion.fromString("My.Relative.Name");
            m_host = Name.Companion.fromString("My.Host.Name.");
            m_admin = Name.Companion.fromString("My.Administrative.Name.");
            m_ttl = randomU16();
            m_serial = randomU32();
            m_refresh = randomU32();
            m_retry = randomU32();
            m_expire = randomU32();
            m_minimum = randomU32();
        }

        public
        void test_0arg() throws UnknownHostException {
            SOARecord ar = new SOARecord();
            assertNull(ar.getName());
            assertEquals(0, ar.getType());
            assertEquals(0, ar.getDclass());
            assertEquals(0, ar.getTtl());
            assertNull(ar.getHost());
            assertNull(ar.getAdmin());
            assertEquals(0, ar.getSerial());
            assertEquals(0, ar.getRefresh());
            assertEquals(0, ar.getRetry());
            assertEquals(0, ar.getExpire());
            assertEquals(0, ar.getMinimum());
        }

        public
        void test_getObject() {
            SOARecord ar = new SOARecord();
            DnsRecord r = ar.getObject();
            assertTrue(r instanceof SOARecord);
        }

        public
        void test_10arg() {
            SOARecord ar = new SOARecord(m_an, DnsClass.IN, m_ttl, m_host, m_admin, m_serial, m_refresh, m_retry, m_expire, m_minimum);
            assertEquals(m_an, ar.getName());
            assertEquals(DnsRecordType.SOA, ar.getType());
            assertEquals(DnsClass.IN, ar.getDclass());
            assertEquals(m_ttl, ar.getTtl());
            assertEquals(m_host, ar.getHost());
            assertEquals(m_admin, ar.getAdmin());
            assertEquals(m_serial, ar.getSerial());
            assertEquals(m_refresh, ar.getRefresh());
            assertEquals(m_retry, ar.getRetry());
            assertEquals(m_expire, ar.getExpire());
            assertEquals(m_minimum, ar.getMinimum());
        }

        public
        void test_10arg_relative_name() {
            try {
                new SOARecord(m_rn, DnsClass.IN, m_ttl, m_host, m_admin, m_serial, m_refresh, m_retry, m_expire, m_minimum);
                fail("RelativeNameException not thrown");
            } catch (RelativeNameException ignored) {
            }
        }

        public
        void test_10arg_relative_host() {
            try {
                new SOARecord(m_an, DnsClass.IN, m_ttl, m_rn, m_admin, m_serial, m_refresh, m_retry, m_expire, m_minimum);
                fail("RelativeNameException not thrown");
            } catch (RelativeNameException ignored) {
            }
        }

        public
        void test_10arg_relative_admin() {
            try {
                new SOARecord(m_an, DnsClass.IN, m_ttl, m_host, m_rn, m_serial, m_refresh, m_retry, m_expire, m_minimum);
                fail("RelativeNameException not thrown");
            } catch (RelativeNameException ignored) {
            }
        }

        public
        void test_10arg_negative_serial() {
            try {
                new SOARecord(m_an, DnsClass.IN, m_ttl, m_host, m_admin, -1, m_refresh, m_retry, m_expire, m_minimum);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException ignored) {
            }
        }

        public
        void test_10arg_toobig_serial() {
            try {
                new SOARecord(m_an, DnsClass.IN, m_ttl, m_host, m_admin, 0x100000000L, m_refresh, m_retry, m_expire, m_minimum);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException ignored) {
            }
        }

        public
        void test_10arg_negative_refresh() {
            try {
                new SOARecord(m_an, DnsClass.IN, m_ttl, m_host, m_admin, m_serial, -1, m_retry, m_expire, m_minimum);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException ignored) {
            }
        }

        public
        void test_10arg_toobig_refresh() {
            try {
                new SOARecord(m_an, DnsClass.IN, m_ttl, m_host, m_admin, m_serial, 0x100000000L, m_retry, m_expire, m_minimum);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException ignored) {
            }
        }

        public
        void test_10arg_negative_retry() {
            try {
                new SOARecord(m_an, DnsClass.IN, m_ttl, m_host, m_admin, m_serial, m_refresh, -1, m_expire, m_minimum);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException ignored) {
            }
        }

        public
        void test_10arg_toobig_retry() {
            try {
                new SOARecord(m_an, DnsClass.IN, m_ttl, m_host, m_admin, m_serial, m_refresh, 0x100000000L, m_expire, m_minimum);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException ignored) {
            }
        }

        public
        void test_10arg_negative_expire() {
            try {
                new SOARecord(m_an, DnsClass.IN, m_ttl, m_host, m_admin, m_serial, m_refresh, m_retry, -1, m_minimum);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException ignored) {
            }
        }

        public
        void test_10arg_toobig_expire() {
            try {
                new SOARecord(m_an, DnsClass.IN, m_ttl, m_host, m_admin, m_serial, m_refresh, m_retry, 0x100000000L, m_minimum);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException ignored) {
            }
        }

        public
        void test_10arg_negative_minimun() {
            try {
                new SOARecord(m_an, DnsClass.IN, m_ttl, m_host, m_admin, m_serial, m_refresh, m_retry, m_expire, -1);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException ignored) {
            }
        }

        public
        void test_10arg_toobig_minimum() {
            try {
                new SOARecord(m_an, DnsClass.IN, m_ttl, m_host, m_admin, m_serial, m_refresh, m_retry, m_expire, 0x100000000L);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException ignored) {
            }
        }
    }


    public static
    class Test_rrFromWire extends TestCase {
        private Name m_host, m_admin;
        private long m_serial, m_refresh, m_retry, m_expire, m_minimum;

        public
        void test() throws IOException {
            byte[] raw = new byte[] {1, 'm', 1, 'h', 1, 'n', 0, // host
                                     1, 'm', 1, 'a', 1, 'n', 0, // admin
                                     (byte) 0xAB, (byte) 0xCD, (byte) 0xEF, (byte) 0x12,       // serial
                                     (byte) 0xCD, (byte) 0xEF, (byte) 0x12, (byte) 0x34,       // refresh
                                     (byte) 0xEF, (byte) 0x12, (byte) 0x34, (byte) 0x56,       // retry
                                     (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78,       // expire
                                     (byte) 0x34, (byte) 0x56, (byte) 0x78, (byte) 0x9A};  // minimum

            DnsInput di = new DnsInput(raw);
            SOARecord ar = new SOARecord();

            ar.rrFromWire(di);

            assertEquals(m_host, ar.getHost());
            assertEquals(m_admin, ar.getAdmin());
            assertEquals(m_serial, ar.getSerial());
            assertEquals(m_refresh, ar.getRefresh());
            assertEquals(m_retry, ar.getRetry());
            assertEquals(m_expire, ar.getExpire());
            assertEquals(m_minimum, ar.getMinimum());
        }        @Override
        protected
        void setUp() throws TextParseException, UnknownHostException {
            m_host = Name.Companion.fromString("M.h.N.");
            m_admin = Name.Companion.fromString("M.a.n.");
            m_serial = 0xABCDEF12L;
            m_refresh = 0xCDEF1234L;
            m_retry = 0xEF123456L;
            m_expire = 0x12345678L;
            m_minimum = 0x3456789AL;
        }


    }


    public static
    class Test_rdataFromString extends TestCase {
        private Name m_host, m_admin, m_origin;
        private long m_serial, m_refresh, m_retry, m_expire, m_minimum;

        public
        void test_valid() throws IOException {
            Tokenizer t = new Tokenizer("M.h " + m_admin + " " + m_serial + " " + m_refresh + " " + m_retry + " " + m_expire + " " +
                                        m_minimum);
            SOARecord ar = new SOARecord();

            ar.rdataFromString(t, m_origin);

            assertEquals(m_host, ar.getHost());
            assertEquals(m_admin, ar.getAdmin());
            assertEquals(m_serial, ar.getSerial());
            assertEquals(m_refresh, ar.getRefresh());
            assertEquals(m_retry, ar.getRetry());
            assertEquals(m_expire, ar.getExpire());
            assertEquals(m_minimum, ar.getMinimum());
        }        @Override
        protected
        void setUp() throws TextParseException, UnknownHostException {
            m_origin = Name.Companion.fromString("O.");
            m_host = Name.Companion.fromString("M.h", m_origin);
            m_admin = Name.Companion.fromString("M.a.n.");
            m_serial = 0xABCDEF12L;
            m_refresh = 0xCDEF1234L;
            m_retry = 0xEF123456L;
            m_expire = 0x12345678L;
            m_minimum = 0x3456789AL;
        }

        public
        void test_relative_name() throws IOException {
            Tokenizer t = new Tokenizer("M.h " + m_admin + " " + m_serial + " " + m_refresh + " " + m_retry + " " + m_expire + " " +
                                        m_minimum);
            SOARecord ar = new SOARecord();

            try {
                ar.rdataFromString(t, null);
                fail("RelativeNameException not thrown");
            } catch (RelativeNameException ignored) {
            }
        }


    }


    public static
    class Test_rrToString extends TestCase {
        private Name m_an, m_host, m_admin;
        private long m_ttl, m_serial, m_refresh, m_retry, m_expire, m_minimum;

        public
        void test_singleLine() {
            SOARecord ar = new SOARecord(m_an, DnsClass.IN, m_ttl, m_host, m_admin, m_serial, m_refresh, m_retry, m_expire, m_minimum);
            String exp = m_host + " " + m_admin + " " + m_serial + " " + m_refresh + " " + m_retry + " " + m_expire + " " + m_minimum;

            StringBuilder sb = new StringBuilder();
            ar.rrToString(sb);
            String out = sb.toString();

            assertEquals(exp, out);
        }        @Override
        protected
        void setUp() throws TextParseException {
            m_an = Name.Companion.fromString("My.absolute.name.");
            m_ttl = 0x13A8;
            m_host = Name.Companion.fromString("M.h.N.");
            m_admin = Name.Companion.fromString("M.a.n.");
            m_serial = 0xABCDEF12L;
            m_refresh = 0xCDEF1234L;
            m_retry = 0xEF123456L;
            m_expire = 0x12345678L;
            m_minimum = 0x3456789AL;
        }

        public
        void test_multiLine() {
            SOARecord ar = new SOARecord(m_an, DnsClass.IN, m_ttl, m_host, m_admin, m_serial, m_refresh, m_retry, m_expire, m_minimum);
            String re = "^.*\\(\\n" + "\\s*" + m_serial + "\\s*;\\s*serial\\n" + // serial
                        "\\s*" + m_refresh + "\\s*;\\s*refresh\\n" + // refresh
                        "\\s*" + m_retry + "\\s*;\\s*retry\\n" + // retry
                        "\\s*" + m_expire + "\\s*;\\s*expire\\n" + // expire
                        "\\s*" + m_minimum + "\\s*\\)\\s*;\\s*minimum$"; // minimum

            Options.INSTANCE.set("multiline");
            StringBuilder sb = new StringBuilder();
            ar.rrToString(sb);
            String out = sb.toString();
            Options.unset("multiline");

            assertTrue(out.matches(re));
        }


    }


    public static
    class Test_rrToWire extends TestCase {
        private Name m_an, m_host, m_admin;
        private long m_ttl, m_serial, m_refresh, m_retry, m_expire, m_minimum;

        public
        void test_canonical() {
            byte[] exp = new byte[] {1, 'm', 1, 'h', 1, 'n', 0, // host
                                     1, 'm', 1, 'a', 1, 'n', 0, // admin
                                     (byte) 0xAB, (byte) 0xCD, (byte) 0xEF, (byte) 0x12,       // serial
                                     (byte) 0xCD, (byte) 0xEF, (byte) 0x12, (byte) 0x34,       // refresh
                                     (byte) 0xEF, (byte) 0x12, (byte) 0x34, (byte) 0x56,       // retry
                                     (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78,       // expire
                                     (byte) 0x34, (byte) 0x56, (byte) 0x78, (byte) 0x9A};  // minimum

            SOARecord ar = new SOARecord(m_an, DnsClass.IN, m_ttl, m_host, m_admin, m_serial, m_refresh, m_retry, m_expire, m_minimum);
            DnsOutput o = new DnsOutput();
            ar.rrToWire(o, null, true);

            assertTrue(Arrays.equals(exp, o.toByteArray()));
        }        @Override
        protected
        void setUp() throws TextParseException {
            m_an = Name.Companion.fromString("My.Abs.Name.");
            m_ttl = 0x13A8;
            m_host = Name.Companion.fromString("M.h.N.");
            m_admin = Name.Companion.fromString("M.a.n.");
            m_serial = 0xABCDEF12L;
            m_refresh = 0xCDEF1234L;
            m_retry = 0xEF123456L;
            m_expire = 0x12345678L;
            m_minimum = 0x3456789AL;
        }

        public
        void test_case_sensitive() {
            byte[] exp = new byte[] {1, 'M', 1, 'h', 1, 'N', 0, // host
                                     1, 'M', 1, 'a', 1, 'n', 0, // admin
                                     (byte) 0xAB, (byte) 0xCD, (byte) 0xEF, (byte) 0x12,       // serial
                                     (byte) 0xCD, (byte) 0xEF, (byte) 0x12, (byte) 0x34,       // refresh
                                     (byte) 0xEF, (byte) 0x12, (byte) 0x34, (byte) 0x56,       // retry
                                     (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78,       // expire
                                     (byte) 0x34, (byte) 0x56, (byte) 0x78, (byte) 0x9A};  // minimum

            SOARecord ar = new SOARecord(m_an, DnsClass.IN, m_ttl, m_host, m_admin, m_serial, m_refresh, m_retry, m_expire, m_minimum);
            DnsOutput o = new DnsOutput();
            ar.rrToWire(o, null, false);

            assertTrue(Arrays.equals(exp, o.toByteArray()));
        }


    }

    public static
    Test suite() {
        TestSuite s = new TestSuite();
        s.addTestSuite(Test_init.class);
        s.addTestSuite(Test_rrFromWire.class);
        s.addTestSuite(Test_rdataFromString.class);
        s.addTestSuite(Test_rrToString.class);
        s.addTestSuite(Test_rrToWire.class);
        return s;
    }
}
