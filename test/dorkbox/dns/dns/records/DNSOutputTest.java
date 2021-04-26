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

import dorkbox.dns.dns.DnsOutput;
import junit.framework.TestCase;

public
class DNSOutputTest extends TestCase {
    private DnsOutput m_do;

    @Override
    public
    void setUp() {
        m_do = new DnsOutput(1);
    }

    public
    void test_default_ctor() {
        m_do = new DnsOutput();
        assertEquals(0, m_do.current());
    }

    public
    void test_initial_state() {
        assertEquals(0, m_do.current());
        try {
            m_do.restore();
            fail("IllegalStateException not thrown");
        } catch (IllegalStateException e) {
            // pass
        }
        try {
            m_do.jump(1);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
            // pass
        }
    }

    public
    void test_writeU8_basic() {
        m_do.writeU8(1);
        assertEquals(1, m_do.current());

        byte[] curr = m_do.toByteArray();
        assertEquals(1, curr.length);
        assertEquals(1, curr[0]);
    }

    public
    void test_writeU8_expand() {
        // starts off at 1;
        m_do.writeU8(1);
        m_do.writeU8(2);

        assertEquals(2, m_do.current());

        byte[] curr = m_do.toByteArray();
        assertEquals(2, curr.length);
        assertEquals(1, curr[0]);
        assertEquals(2, curr[1]);
    }

    public
    void test_writeU8_max() {
        m_do.writeU8(0xFF);
        byte[] curr = m_do.toByteArray();
        assertEquals((byte) 0xFF, (byte) curr[0]);
    }

    public
    void test_writeU8_toobig() {
        try {
            m_do.writeU8(0x1FF);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
            // pass
        }
    }

    public
    void test_writeU16_basic() {
        m_do.writeU16(0x100);
        assertEquals(2, m_do.current());

        byte[] curr = m_do.toByteArray();
        assertEquals(2, curr.length);
        assertEquals(1, curr[0]);
        assertEquals(0, curr[1]);
    }

    public
    void test_writeU16_max() {
        m_do.writeU16(0xFFFF);
        byte[] curr = m_do.toByteArray();
        assertEquals((byte) 0xFF, (byte) curr[0]);
        assertEquals((byte) 0XFF, (byte) curr[1]);
    }

    public
    void test_writeU16_toobig() {
        try {
            m_do.writeU16(0x1FFFF);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
            // pass
        }
    }

    public
    void test_writeU32_basic() {
        m_do.writeU32(0x11001011);
        assertEquals(4, m_do.current());

        byte[] curr = m_do.toByteArray();
        assertEquals(4, curr.length);
        assertEquals(0x11, curr[0]);
        assertEquals(0x00, curr[1]);
        assertEquals(0x10, curr[2]);
        assertEquals(0x11, curr[3]);
    }

    public
    void test_writeU32_max() {
        m_do.writeU32(0xFFFFFFFFL);
        byte[] curr = m_do.toByteArray();
        assertEquals((byte) 0xFF, (byte) curr[0]);
        assertEquals((byte) 0XFF, (byte) curr[1]);
        assertEquals((byte) 0XFF, (byte) curr[2]);
        assertEquals((byte) 0XFF, (byte) curr[3]);
    }

    public
    void test_writeU32_toobig() {
        try {
            m_do.writeU32(0x1FFFFFFFFL);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
            // pass
        }
    }

    public
    void test_jump_basic() {
        m_do.writeU32(0x11223344L);
        assertEquals(4, m_do.current());
        m_do.jump(2);
        assertEquals(2, m_do.current());
        m_do.writeU8(0x99);
        byte[] curr = m_do.toByteArray();
        assertEquals(3, curr.length);
        assertEquals(0x11, curr[0]);
        assertEquals(0x22, curr[1]);
        assertEquals((byte) 0x99, (byte) curr[2]);

    }

    public
    void test_writeByteArray_1arg() {
        byte[] in = new byte[] {(byte) 0xAB, (byte) 0xCD, (byte) 0xEF, (byte) 0x12, (byte) 0x34};
        m_do.writeByteArray(in);
        assertEquals(5, m_do.current());
        byte[] curr = m_do.toByteArray();
        assertEquals(in, curr);
    }

    private
    void assertEquals(byte[] exp, byte[] act) {
        assertTrue(java.util.Arrays.equals(exp, act));
    }

    public
    void test_writeByteArray_3arg() {
        byte[] in = new byte[] {(byte) 0xAB, (byte) 0xCD, (byte) 0xEF, (byte) 0x12, (byte) 0x34};
        m_do.writeByteArray(in, 2, 3);
        assertEquals(3, m_do.current());
        byte[] exp = new byte[] {in[2], in[3], in[4]};
        byte[] curr = m_do.toByteArray();
        assertEquals(exp, curr);
    }

    public
    void test_writeCountedString_basic() {
        byte[] in = new byte[] {'h', 'e', 'l', 'L', '0'};
        m_do.writeCountedString(in);
        assertEquals(in.length + 1, m_do.current());
        byte[] curr = m_do.toByteArray();
        byte[] exp = new byte[] {(byte) (in.length), in[0], in[1], in[2], in[3], in[4]};
        assertEquals(exp, curr);
    }

    public
    void test_writeCountedString_empty() {
        byte[] in = new byte[] {};
        m_do.writeCountedString(in);
        assertEquals(in.length + 1, m_do.current());
        byte[] curr = m_do.toByteArray();
        byte[] exp = new byte[] {(byte) (in.length)};
        assertEquals(exp, curr);
    }

    public
    void test_writeCountedString_toobig() {
        byte[] in = new byte[256];
        try {
            m_do.writeCountedString(in);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
            // pass
        }
    }

    public
    void test_save_restore() {
        m_do.writeU32(0x12345678L);
        assertEquals(4, m_do.current());
        m_do.save();
        m_do.writeU16(0xABCD);
        assertEquals(6, m_do.current());
        m_do.restore();
        assertEquals(4, m_do.current());
        try {
            m_do.restore();
            fail("IllegalArgumentException not thrown");
        } catch (IllegalStateException e) {
            // pass
        }
    }

}
