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
class ARecordTest extends TestCase {
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
        m_addr_string = "193.160.232.5";
        m_addr = InetAddress.getByName(m_addr_string);
        m_addr_bytes = m_addr.getAddress();
        m_ttl = 0x13579;
    }

    public
    void test_ctor_0arg() throws UnknownHostException {
        ARecord ar = new ARecord();
        assertNull(ar.getName());
        assertEquals(0, ar.getType());
        assertEquals(0, ar.getDclass());
        assertEquals(0, ar.getTtl());
        assertEquals(InetAddress.getByName("0.0.0.0"), ar.getAddress());
    }

    public
    void test_getObject() {
        ARecord ar = new ARecord();
        DnsRecord r = ar.getObject();
        assertTrue(r instanceof ARecord);
    }

    public
    void test_ctor_4arg() {
        ARecord ar = new ARecord(m_an, DnsClass.IN, m_ttl, m_addr);
        assertEquals(m_an, ar.getName());
        assertEquals(DnsRecordType.A, ar.getType());
        assertEquals(DnsClass.IN, ar.getDclass());
        assertEquals(m_ttl, ar.getTtl());
        assertEquals(m_addr, ar.getAddress());

        // a relative name
        try {
            new ARecord(m_rn, DnsClass.IN, m_ttl, m_addr);
            fail("RelativeNameException not thrown");
        } catch (RelativeNameException e) {
        }

        // an IPv6 address
        try {
            new ARecord(m_an, DnsClass.IN, m_ttl, InetAddress.getByName("2001:0db8:85a3:08d3:1319:8a2e:0370:7334"));
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        } catch (UnknownHostException e) {
            fail(e.getMessage());
        }
    }

    public
    void test_rrFromWire() throws IOException {
        DnsInput di = new DnsInput(m_addr_bytes);
        ARecord ar = new ARecord();

        ar.rrFromWire(di);

        assertEquals(m_addr, ar.getAddress());
    }

    public
    void test_rdataFromString() throws IOException {
        Tokenizer t = new Tokenizer(m_addr_string);
        ARecord ar = new ARecord();

        ar.rdataFromString(t, null);

        assertEquals(m_addr, ar.getAddress());

        // invalid address
        t = new Tokenizer("193.160.232");
        ar = new ARecord();
        try {
            ar.rdataFromString(t, null);
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }
    }

    public
    void test_rrToString() {
        ARecord ar = new ARecord(m_an, DnsClass.IN, m_ttl, m_addr);
        StringBuilder sb = new StringBuilder();
        ar.rrToString(sb);
        assertEquals(m_addr_string, sb.toString());
    }

    public
    void test_rrToWire() {
        ARecord ar = new ARecord(m_an, DnsClass.IN, m_ttl, m_addr);
        DnsOutput dout = new DnsOutput();

        ar.rrToWire(dout, null, true);
        assertTrue(Arrays.equals(m_addr_bytes, dout.toByteArray()));

        dout = new DnsOutput();
        ar.rrToWire(dout, null, false);
        assertTrue(Arrays.equals(m_addr_bytes, dout.toByteArray()));
    }
}
