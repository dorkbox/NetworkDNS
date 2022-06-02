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
class A6RecordTest extends TestCase {
    Name m_an, m_an2, m_rn;
    InetAddress m_addr;
    String m_addr_string, m_addr_string_canonical;
    byte[] m_addr_bytes;
    int m_prefix_bits;
    long m_ttl;

    @Override
    protected
    void setUp() throws TextParseException, UnknownHostException {
        m_an = Name.Companion.fromString("My.Absolute.Name.");
        m_an2 = Name.Companion.fromString("My.Second.Absolute.Name.");
        m_rn = Name.Companion.fromString("My.Relative.Name");
        m_addr_string = "2001:0db8:85a3:08d3:1319:8a2e:0370:7334";
        m_addr_string_canonical = "2001:db8:85a3:8d3:1319:8a2e:370:7334";
        m_addr = InetAddress.getByName(m_addr_string);
        m_addr_bytes = m_addr.getAddress();
        m_ttl = 0x13579;
        m_prefix_bits = 9;
    }

    public
    void test_ctor_0arg() {
        A6Record ar = new A6Record();
        assertNull(ar.getName());
        assertEquals(0, ar.getType());
        assertEquals(0, ar.getDclass());
        assertEquals(0, ar.getTtl());
    }

    public
    void test_getObject() {
        A6Record ar = new A6Record();
        DnsRecord r = ar.getObject();
        assertTrue(r instanceof A6Record);
    }

    public
    void test_ctor_6arg() {
        A6Record ar = new A6Record(m_an, DnsClass.IN, m_ttl, m_prefix_bits, m_addr, null);
        assertEquals(m_an, ar.getName());
        assertEquals(DnsRecordType.A6, ar.getType());
        assertEquals(DnsClass.IN, ar.getDclass());
        assertEquals(m_ttl, ar.getTtl());
        assertEquals(m_prefix_bits, ar.getPrefixBits());
        assertEquals(m_addr, ar.getSuffix());
        assertNull(ar.getPrefix());

        // with the prefix name
        ar = new A6Record(m_an, DnsClass.IN, m_ttl, m_prefix_bits, m_addr, m_an2);
        assertEquals(m_an, ar.getName());
        assertEquals(DnsRecordType.A6, ar.getType());
        assertEquals(DnsClass.IN, ar.getDclass());
        assertEquals(m_ttl, ar.getTtl());
        assertEquals(m_prefix_bits, ar.getPrefixBits());
        assertEquals(m_addr, ar.getSuffix());
        assertEquals(m_an2, ar.getPrefix());

        // a relative name
        try {
            new A6Record(m_rn, DnsClass.IN, m_ttl, m_prefix_bits, m_addr, null);
            fail("RelativeNameException not thrown");
        } catch (RelativeNameException e) {
        }

        // a relative prefix name
        try {
            new A6Record(m_an, DnsClass.IN, m_ttl, m_prefix_bits, m_addr, m_rn);
            fail("RelativeNameException not thrown");
        } catch (RelativeNameException e) {
        }

        // invalid prefix bits
        try {
            new A6Record(m_rn, DnsClass.IN, m_ttl, 0x100, m_addr, null);
            fail("IllegalArgumentException not thrown");
        } catch (RelativeNameException e) {
        }

        // an IPv4 address
        try {
            new A6Record(m_an, DnsClass.IN, m_ttl, m_prefix_bits, InetAddress.getByName("192.168.0.1"), null);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        } catch (UnknownHostException e) {
            fail(e.getMessage());
        }
    }

    public
    void test_rrFromWire() throws CloneNotSupportedException, IOException, UnknownHostException {
        // record with no prefix
        DnsOutput dout = new DnsOutput();
        dout.writeU8(0);
        dout.writeByteArray(m_addr_bytes);

        DnsInput din = new DnsInput(dout.toByteArray());
        A6Record ar = new A6Record();
        ar.rrFromWire(din);
        assertEquals(0, ar.getPrefixBits());
        assertEquals(m_addr, ar.getSuffix());
        assertNull(ar.getPrefix());

        // record with 9 bit prefix (should result in 15 bytes of the address)
        dout = new DnsOutput();
        dout.writeU8(9);
        dout.writeByteArray(m_addr_bytes, 1, 15);
        dout.writeByteArray(m_an2.toWire());

        din = new DnsInput(dout.toByteArray());
        ar = new A6Record();
        ar.rrFromWire(din);
        assertEquals(9, ar.getPrefixBits());

        byte[] addr_bytes = (byte[]) m_addr_bytes.clone();
        addr_bytes[0] = 0;
        InetAddress exp = InetAddress.getByAddress(addr_bytes);
        assertEquals(exp, ar.getSuffix());
        assertEquals(m_an2, ar.getPrefix());
    }

    public
    void test_rdataFromString() throws CloneNotSupportedException, IOException, UnknownHostException {
        // record with no prefix
        Tokenizer t = new Tokenizer("0 " + m_addr_string);
        A6Record ar = new A6Record();
        ar.rdataFromString(t, null);
        assertEquals(0, ar.getPrefixBits());
        assertEquals(m_addr, ar.getSuffix());
        assertNull(ar.getPrefix());

        // record with 9 bit prefix.  In contrast to the rrFromWire method,
        // rdataFromString expects the entire 128 bits to be represented
        // in the string
        t = new Tokenizer("9 " + m_addr_string + " " + m_an2);
        ar = new A6Record();
        ar.rdataFromString(t, null);
        assertEquals(9, ar.getPrefixBits());
        assertEquals(m_addr, ar.getSuffix());
        assertEquals(m_an2, ar.getPrefix());

        // record with invalid prefixBits
        t = new Tokenizer("129");
        ar = new A6Record();
        try {
            ar.rdataFromString(t, null);
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }

        // record with invalid ipv6 address
        t = new Tokenizer("0 " + m_addr_string.substring(4));
        ar = new A6Record();
        try {
            ar.rdataFromString(t, null);
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }
    }

    public
    void test_rrToString() {
        A6Record ar = new A6Record(m_an, DnsClass.IN, m_ttl, m_prefix_bits, m_addr, m_an2);
        String exp = "" + m_prefix_bits + " " + m_addr_string_canonical + " " + m_an2;
        StringBuilder stringBuilder = new StringBuilder();

        ar.rrToString(stringBuilder);
        String out = stringBuilder.toString();
        assertEquals(exp, out);
    }

    public
    void test_rrToWire() {
        // canonical form
        A6Record ar = new A6Record(m_an, DnsClass.IN, m_ttl, m_prefix_bits, m_addr, m_an2);
        DnsOutput dout = new DnsOutput();
        dout.writeU8(m_prefix_bits);
        dout.writeByteArray(m_addr_bytes, 1, 15);
        dout.writeByteArray(m_an2.toWireCanonical());

        byte[] exp = dout.toByteArray();

        dout = new DnsOutput();
        ar.rrToWire(dout, null, true);

        assertTrue(Arrays.equals(exp, dout.toByteArray()));

        // case sensitiveform
        dout = new DnsOutput();
        dout.writeU8(m_prefix_bits);
        dout.writeByteArray(m_addr_bytes, 1, 15);
        dout.writeByteArray(m_an2.toWire());

        exp = dout.toByteArray();

        dout = new DnsOutput();
        ar.rrToWire(dout, null, false);
        assertTrue(Arrays.equals(exp, dout.toByteArray()));
    }
}
