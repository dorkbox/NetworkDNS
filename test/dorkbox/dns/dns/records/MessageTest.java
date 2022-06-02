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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsClass;
import dorkbox.dns.dns.constants.DnsOpCode;
import dorkbox.dns.dns.constants.DnsSection;
import dorkbox.dns.dns.constants.Flags;
import dorkbox.dns.dns.exceptions.TextParseException;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public
class MessageTest {
    public static
    class Test_init extends TestCase {
        public
        void test_0arg() {
            DnsMessage m = new DnsMessage();
            assertTrue(Arrays.equals(new DnsRecord[0], m.getSectionArray(0)));
            assertTrue(Arrays.equals(new DnsRecord[0], m.getSectionArray(1)));
            assertTrue(Arrays.equals(new DnsRecord[0], m.getSectionArray(2)));
            assertTrue(Arrays.equals(new DnsRecord[0], m.getSectionArray(3)));
            try {
                m.getSectionArray(4);
                fail("IndexOutOfBoundsException not thrown");
            } catch (IndexOutOfBoundsException ignored) {
            }
            Header h = m.getHeader();
            assertEquals(0, h.getCount(0));
            assertEquals(0, h.getCount(1));
            assertEquals(0, h.getCount(2));
            assertEquals(0, h.getCount(3));
        }

        public
        void test_1arg() {
            DnsMessage m = new DnsMessage(10);
            assertEquals(new Header(10).toString(),
                         m.getHeader()
                          .toString());
            assertTrue(Arrays.equals(new DnsRecord[0], m.getSectionArray(0)));
            assertTrue(Arrays.equals(new DnsRecord[0], m.getSectionArray(1)));
            assertTrue(Arrays.equals(new DnsRecord[0], m.getSectionArray(2)));
            assertTrue(Arrays.equals(new DnsRecord[0], m.getSectionArray(3)));
            try {
                m.getSectionArray(4);
                fail("IndexOutOfBoundsException not thrown");
            } catch (IndexOutOfBoundsException ignored) {
            }
            Header h = m.getHeader();
            assertEquals(0, h.getCount(0));
            assertEquals(0, h.getCount(1));
            assertEquals(0, h.getCount(2));
            assertEquals(0, h.getCount(3));
        }

        public
        void test_newQuery() throws TextParseException, UnknownHostException {
            Name n = Name.Companion.fromString("The.Name.");
            ARecord ar = new ARecord(n, DnsClass.IN, 1, InetAddress.getByName("192.168.101.110"));

            DnsMessage m = DnsMessage.newQuery(ar);
            assertTrue(Arrays.equals(new DnsRecord[] {ar}, m.getSectionArray(DnsSection.QUESTION)));
            assertTrue(Arrays.equals(new DnsRecord[0], m.getSectionArray(DnsSection.ANSWER)));
            assertTrue(Arrays.equals(new DnsRecord[0], m.getSectionArray(DnsSection.AUTHORITY)));
            assertTrue(Arrays.equals(new DnsRecord[0], m.getSectionArray(DnsSection.ADDITIONAL)));

            Header h = m.getHeader();
            assertEquals(1, h.getCount(DnsSection.QUESTION));
            assertEquals(0, h.getCount(DnsSection.ANSWER));
            assertEquals(0, h.getCount(DnsSection.AUTHORITY));
            assertEquals(0, h.getCount(DnsSection.ADDITIONAL));
            assertEquals(DnsOpCode.QUERY, h.getOpcode());
            assertEquals(true, h.getFlag(Flags.RD));
        }

    }

    public static
    Test suite() {
        TestSuite s = new TestSuite();
        s.addTestSuite(Test_init.class);
        return s;
    }
}
