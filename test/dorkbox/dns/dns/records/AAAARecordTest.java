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
import java.util.Arrays;

import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsClass;
import dorkbox.dns.dns.constants.DnsRecordType;
import dorkbox.dns.dns.exceptions.RelativeNameException;
import dorkbox.dns.dns.exceptions.TextParseException;
import dorkbox.dns.dns.utils.Tokenizer;
import junit.framework.TestCase;

public
class AAAARecordTest extends TestCase {
    Name m_an, m_rn;
    InetAddress m_addr;
    String m_addr_string;
    byte[] m_addr_bytes;
    long m_ttl;

    @Override
    protected
    void setUp() throws TextParseException, UnknownHostException {
        m_an = Name.Companion.fromString("My.Absolute.Name.");
        m_rn = Name.Companion.fromString("My.Relative.Name");
        m_addr_string = "2001:db8:85a3:8d3:1319:8a2e:370:7334";
        m_addr = InetAddress.getByName(m_addr_string);
        m_addr_bytes = m_addr.getAddress();
        m_ttl = 0x13579;
    }

    public
    void test_ctor_0arg() throws UnknownHostException {
        AAAARecord ar = new AAAARecord();
        assertNull(ar.getName());
        assertEquals(0, ar.getType());
        assertEquals(0, ar.getDclass());
        assertEquals(0, ar.getTtl());
        assertNull(ar.getAddress());
    }

    public
    void test_getObject() {
        AAAARecord ar = new AAAARecord();
        DnsRecord r = ar.getObject();
        assertTrue(r instanceof AAAARecord);
    }

    public
    void test_ctor_4arg() {
        AAAARecord ar = new AAAARecord(m_an, DnsClass.IN, m_ttl, m_addr);
        assertEquals(m_an, ar.getName());
        assertEquals(DnsRecordType.AAAA, ar.getType());
        assertEquals(DnsClass.IN, ar.getDclass());
        assertEquals(m_ttl, ar.getTtl());
        assertEquals(m_addr, ar.getAddress());

        // a relative name
        try {
            new AAAARecord(m_rn, DnsClass.IN, m_ttl, m_addr);
            fail("RelativeNameException not thrown");
        } catch (RelativeNameException e) {
        }

        // an IPv4 address
        try {
            new AAAARecord(m_an, DnsClass.IN, m_ttl, InetAddress.getByName("192.168.0.1"));
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        } catch (UnknownHostException e) {
            fail(e.getMessage());
        }
    }

    public
    void test_rrFromWire() throws IOException {
        DnsInput di = new DnsInput(m_addr_bytes);
        AAAARecord ar = new AAAARecord();

        ar.rrFromWire(di);

        assertEquals(m_addr, ar.getAddress());
    }

    public
    void test_rdataFromString() throws IOException {
        Tokenizer t = new Tokenizer(m_addr_string);
        AAAARecord ar = new AAAARecord();

        ar.rdataFromString(t, null);

        assertEquals(m_addr, ar.getAddress());

        // invalid address
        t = new Tokenizer("193.160.232.1");
        ar = new AAAARecord();
        try {
            ar.rdataFromString(t, null);
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }
    }

    public
    void test_rrToString() {
        AAAARecord ar = new AAAARecord(m_an, DnsClass.IN, m_ttl, m_addr);
        StringBuilder sb = new StringBuilder();
        ar.rrToString(sb);
        assertEquals(m_addr_string, sb.toString());
    }

    public
    void test_rrToWire() {
        AAAARecord ar = new AAAARecord(m_an, DnsClass.IN, m_ttl, m_addr);

        // canonical
        DnsOutput dout = new DnsOutput();
        ar.rrToWire(dout, null, true);
        assertTrue(Arrays.equals(m_addr_bytes, dout.toByteArray()));

        // case sensitive
        dout = new DnsOutput();
        ar.rrToWire(dout, null, false);
        assertTrue(Arrays.equals(m_addr_bytes, dout.toByteArray()));
    }
}
