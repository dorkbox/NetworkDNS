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
import dorkbox.dns.dns.constants.DnsOpCode;
import dorkbox.dns.dns.constants.DnsResponseCode;
import dorkbox.dns.dns.constants.Flags;
import junit.framework.TestCase;

public
class HeaderTest extends TestCase {
    private Header m_h;

    @Override
    public
    void setUp() {
        m_h = new Header(0xABCD); // 43981
    }

    public
    void test_fixture_state() {
        assertEquals(0xABCD, m_h.getID());

        boolean[] flags = m_h.getFlags();
        for (int i = 0; i < flags.length; ++i) {
            assertFalse(flags[i]);
        }
        assertEquals(0, m_h.getRcode());
        assertEquals(0, m_h.getOpcode());
        assertEquals(0, m_h.getCount(0));
        assertEquals(0, m_h.getCount(1));
        assertEquals(0, m_h.getCount(2));
        assertEquals(0, m_h.getCount(3));
    }

    public
    void test_ctor_0arg() {
        m_h = new Header();
        assertTrue(0 <= m_h.getID() && m_h.getID() < 0xFFFF);

        boolean[] flags = m_h.getFlags();
        for (int i = 0; i < flags.length; ++i) {
            assertFalse(flags[i]);
        }
        assertEquals(0, m_h.getRcode());
        assertEquals(0, m_h.getOpcode());
        assertEquals(0, m_h.getCount(0));
        assertEquals(0, m_h.getCount(1));
        assertEquals(0, m_h.getCount(2));
        assertEquals(0, m_h.getCount(3));
    }

    public
    void test_ctor_DNSInput() throws IOException {
        byte[] raw = new byte[] {(byte) 0x12, (byte) 0xAB, // ID
                                 (byte) 0x8F, (byte) 0xBD, // flags: 1 0001 1 1 1 1 011 1101
                                 (byte) 0x65, (byte) 0x1C, // QDCOUNT
                                 (byte) 0x10, (byte) 0xF0, // ANCOUNT
                                 (byte) 0x98, (byte) 0xBA, // NSCOUNT
                                 (byte) 0x71, (byte) 0x90}; // ARCOUNT

        m_h = new Header(new DnsInput(raw));

        assertEquals(0x12AB, m_h.getID());

        boolean[] flags = m_h.getFlags();

        assertTrue(flags[0]);

        assertEquals(1, m_h.getOpcode());

        assertTrue(flags[5]);

        assertTrue(flags[6]);

        assertTrue(flags[7]);

        assertTrue(flags[8]);

        assertFalse(flags[9]);
        assertTrue(flags[10]);
        assertTrue(flags[11]);

        assertEquals(0xD, m_h.getRcode());

        assertEquals(0x651C, m_h.getCount(0));
        assertEquals(0x10F0, m_h.getCount(1));
        assertEquals(0x98BA, m_h.getCount(2));
        assertEquals(0x7190, m_h.getCount(3));
    }

    public
    void test_toWire() throws IOException {
        byte[] raw = new byte[] {(byte) 0x12, (byte) 0xAB, // ID
                                 (byte) 0x8F, (byte) 0xBD, // flags: 1 0001 1 1 1 1 011 1101
                                 (byte) 0x65, (byte) 0x1C, // QDCOUNT
                                 (byte) 0x10, (byte) 0xF0, // ANCOUNT
                                 (byte) 0x98, (byte) 0xBA, // NSCOUNT
                                 (byte) 0x71, (byte) 0x90}; // ARCOUNT

        m_h = new Header(raw);

        DnsOutput dout = new DnsOutput();
        m_h.toWire(dout);

        byte[] out = dout.toByteArray();

        assertEquals(12, out.length);
        for (int i = 0; i < out.length; ++i) {
            assertEquals(raw[i], out[i]);
        }

        m_h.setOpcode(0xA); // 1010
        assertEquals(0xA, m_h.getOpcode());
        m_h.setRcode(0x7);  // 0111

        // flags is now: 1101 0111 1011 0111

        raw[2] = (byte) 0xD7;
        raw[3] = (byte) 0xB7;

        out = m_h.toWire();

        assertEquals(12, out.length);
        for (int i = 0; i < out.length; ++i) {
            assertEquals("i=" + i, raw[i], out[i]);
        }
    }

    public
    void test_flags() {
        m_h.setFlag(Flags.Companion.toFlag(0));
        m_h.setFlag(Flags.Companion.toFlag(5));
        assertTrue(m_h.getFlag(Flags.Companion.toFlag(0)));
        assertTrue(m_h.getFlags()[0]);
        assertTrue(m_h.getFlag(Flags.Companion.toFlag(5)));
        assertTrue(m_h.getFlags()[5]);

        m_h.unsetFlag(Flags.Companion.toFlag(0));
        assertFalse(m_h.getFlag(Flags.Companion.toFlag(0)));
        assertFalse(m_h.getFlags()[0]);
        assertTrue(m_h.getFlag(Flags.Companion.toFlag(5)));
        assertTrue(m_h.getFlags()[5]);

        m_h.unsetFlag(Flags.Companion.toFlag(5));
        assertFalse(m_h.getFlag(Flags.Companion.toFlag(0)));
        assertFalse(m_h.getFlags()[0]);
        assertFalse(m_h.getFlag(Flags.Companion.toFlag(5)));
        assertFalse(m_h.getFlags()[5]);

        boolean[] flags = m_h.getFlags();
        for (int i = 0; i < flags.length; ++i) {
            if ((i > 0 && i < 5) || i > 11) {
                continue;
            }
            assertFalse(flags[i]);
        }
    }

    public
    void test_flags_invalid() {
        try {
            m_h.setFlag(Flags.Companion.toFlag(-1));
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
        try {
            m_h.setFlag(Flags.Companion.toFlag(1));
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
        try {
            m_h.setFlag(Flags.Companion.toFlag(16));
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
        try {
            m_h.unsetFlag(Flags.Companion.toFlag(-1));
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
        try {
            m_h.unsetFlag(Flags.Companion.toFlag(13));
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
        try {
            m_h.unsetFlag(Flags.Companion.toFlag(16));
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
        try {
            m_h.getFlag(Flags.Companion.toFlag(-1));
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
        try {
            m_h.getFlag(Flags.Companion.toFlag(4));
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
        try {
            m_h.getFlag(Flags.Companion.toFlag(16));
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    public
    void test_ID() {
        assertEquals(0xABCD, m_h.getID());

        m_h = new Header();

        int id = m_h.getID();
        assertEquals(id, m_h.getID());
        assertTrue(id >= 0 && id < 0xffff);

        m_h.setID(0xDCBA);
        assertEquals(0xDCBA, m_h.getID());
    }

    public
    void test_setID_invalid() {
        try {
            m_h.setID(0x10000);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
        try {
            m_h.setID(-1);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    public
    void test_Rcode() {
        assertEquals(0, m_h.getRcode());

        m_h.setRcode(0xA); // 1010
        assertEquals(0xA, m_h.getRcode());
        for (int i = 0; i < 12; ++i) {
            if ((i > 0 && i < 5) || i > 11) {
                continue;
            }
            assertFalse(m_h.getFlag(Flags.Companion.toFlag(i)));
        }
    }

    public
    void test_setRcode_invalid() {
        try {
            m_h.setRcode(-1);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
        try {
            m_h.setRcode(0x100);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    public
    void test_Opcode() {
        assertEquals(0, m_h.getOpcode());

        m_h.setOpcode(0xE); // 1110
        assertEquals(0xE, m_h.getOpcode());

        assertFalse(m_h.getFlag(Flags.Companion.toFlag(0)));
        for (int i = 5; i < 12; ++i) {
            assertFalse(m_h.getFlag(Flags.Companion.toFlag(i)));
        }
        assertEquals(0, m_h.getRcode());
    }

    public
    void test_setOpcode_invalid() {
        try {
            m_h.setOpcode(-1);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
        try {
            m_h.setOpcode(0x100);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    public
    void test_Count() {
        m_h.setCount(2, 0x1E);
        assertEquals(0, m_h.getCount(0));
        assertEquals(0, m_h.getCount(1));
        assertEquals(0x1E, m_h.getCount(2));
        assertEquals(0, m_h.getCount(3));

        m_h.incCount(0);
        assertEquals(1, m_h.getCount(0));

        m_h.decCount(2);
        assertEquals(0x1E - 1, m_h.getCount(2));
    }

    public
    void test_setCount_invalid() {
        try {
            m_h.setCount(-1, 0);
            fail("ArrayIndexOutOfBoundsException not thrown");
        } catch (ArrayIndexOutOfBoundsException e) {
        }
        try {
            m_h.setCount(4, 0);
            fail("ArrayIndexOutOfBoundsException not thrown");
        } catch (ArrayIndexOutOfBoundsException e) {
        }

        try {
            m_h.setCount(0, -1);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
        try {
            m_h.setCount(3, 0x10000);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    public
    void test_getCount_invalid() {
        try {
            m_h.getCount(-1);
            fail("ArrayIndexOutOfBoundsException not thrown");
        } catch (ArrayIndexOutOfBoundsException e) {
        }
        try {
            m_h.getCount(4);
            fail("ArrayIndexOutOfBoundsException not thrown");
        } catch (ArrayIndexOutOfBoundsException e) {
        }
    }

    public
    void test_incCount_invalid() {
        m_h.setCount(1, 0xFFFF);
        try {
            m_h.incCount(1);
            fail("IllegalStateException not thrown");
        } catch (IllegalStateException e) {
        }
    }

    public
    void test_decCount_invalid() {
        m_h.setCount(2, 0);
        try {
            m_h.decCount(2);
            fail("IllegalStateException not thrown");
        } catch (IllegalStateException e) {
        }
    }

    public
    void test_toString() {
        m_h.setOpcode(DnsOpCode.STATUS);
        m_h.setRcode(DnsResponseCode.NXDOMAIN);
        m_h.setFlag(Flags.QR); // qr
        m_h.setFlag(Flags.RD); // rd
        m_h.setFlag(Flags.RA); // ra
        m_h.setFlag(Flags.CD); // cd
        m_h.setCount(1, 0xFF);
        m_h.setCount(2, 0x0A);


        String text = m_h.toString();

        assertFalse(text.indexOf("id: 43981") == -1);
        assertFalse(text.indexOf("opcode: STATUS") == -1);
        assertFalse(text.indexOf("status: NXDOMAIN") == -1);
        assertFalse(text.indexOf(" qr ") == -1);
        assertFalse(text.indexOf(" rd ") == -1);
        assertFalse(text.indexOf(" ra ") == -1);
        assertFalse(text.indexOf(" cd ") == -1);
        assertFalse(text.indexOf("qd: 0 ") == -1);
        assertFalse(text.indexOf("an: 255 ") == -1);
        assertFalse(text.indexOf("au: 10 ") == -1);
        assertFalse(text.indexOf("ad: 0 ") == -1);
    }

    public
    void test_clone() {
        m_h.setOpcode(DnsOpCode.IQUERY);
        m_h.setRcode(DnsResponseCode.SERVFAIL);
        m_h.setFlag(Flags.QR); // qr
        m_h.setFlag(Flags.RD); // rd
        m_h.setFlag(Flags.RA); // ra
        m_h.setFlag(Flags.CD); // cd
        m_h.setCount(1, 0xFF);
        m_h.setCount(2, 0x0A);

        Header h2 = (Header) m_h.clone();

        assertNotSame(m_h, h2);
        assertEquals(m_h.getID(), h2.getID());
        for (int i = 0; i < 16; ++i) {
            if ((i > 0 && i < 5) || i > 11) {
                continue;
            }
            assertEquals(m_h.getFlag(Flags.Companion.toFlag(i)), h2.getFlag(Flags.Companion.toFlag(i)));
        }
        for (int i = 0; i < 4; ++i) {
            assertEquals(m_h.getCount(i), h2.getCount(i));
        }
    }
}
