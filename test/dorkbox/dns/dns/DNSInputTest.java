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
package dorkbox.dns.dns;

import java.util.Arrays;

import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.exceptions.WireParseException;
import junit.framework.TestCase;

public
class DNSInputTest extends TestCase {
    private byte[] m_raw;
    private DnsInput m_di;

    @Override
    public
    void setUp() {
        m_raw = new byte[] {0, 1, 2, 3, 4, 5, (byte) 255, (byte) 255, (byte) 255, (byte) 255};
        m_di = new DnsInput(m_raw);
    }

    public
    void test_initial_state() {
        assertEquals(0, m_di.readIndex());
        assertEquals(10, m_di.remaining());
    }

    public
    void test_jump1() {
        m_di.jump(1);
        assertEquals(1, m_di.readIndex());
        assertEquals(9, m_di.remaining());
    }

    public
    void test_jump2() {
        m_di.jump(9);
        assertEquals(9, m_di.readIndex());
        assertEquals(1, m_di.remaining());
    }

    public
    void test_jump_invalid() {
        try {
            m_di.jump(10);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
            // pass
        }
    }

    public
    void test_setActive() {
        m_di.setActive(5);
        assertEquals(0, m_di.readIndex());
        assertEquals(5, m_di.remaining());
    }

    public
    void test_setActive_boundary1() {
        m_di.setActive(10);
        assertEquals(0, m_di.readIndex());
        assertEquals(10, m_di.remaining());
    }

    public
    void test_setActive_boundary2() {
        m_di.setActive(0);
        assertEquals(0, m_di.readIndex());
        assertEquals(0, m_di.remaining());
    }

    public
    void test_setActive_invalid() {
        try {
            m_di.setActive(11);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
            // pass
        }
    }

    public
    void test_clearActive() {
        // first without setting active:
        m_di.restoreActive();
        assertEquals(0, m_di.readIndex());
        assertEquals(10, m_di.remaining());

        m_di.setActive(5);
        m_di.restoreActive();
        assertEquals(0, m_di.readIndex());
        assertEquals(10, m_di.remaining());
    }

    public
    void test_restore_invalid() {
        try {
            m_di.restore();
            fail("IllegalStateException not thrown");
        } catch (IllegalStateException e) {
            // pass
        }
    }

    public
    void test_save_restore() {
        m_di.jump(4);
        assertEquals(4, m_di.readIndex());
        assertEquals(6, m_di.remaining());

        m_di.save();
        m_di.jump(0);
        assertEquals(0, m_di.readIndex());
        assertEquals(10, m_di.remaining());

        m_di.restore();
        assertEquals(4, m_di.readIndex());
        assertEquals(6, m_di.remaining());
    }

    public
    void test_readU8_basic() throws WireParseException {
        int v1 = m_di.readU8();
        assertEquals(1, m_di.readIndex());
        assertEquals(9, m_di.remaining());
        assertEquals(0, v1);
    }

    public
    void test_readU8_maxval() throws WireParseException {
        m_di.jump(9);
        int v1 = m_di.readU8();
        assertEquals(10, m_di.readIndex());
        assertEquals(0, m_di.remaining());
        assertEquals(255, v1);

        try {
            v1 = m_di.readU8();
            fail("WireParseException not thrown");
        } catch (WireParseException e) {
            // pass
        }
    }

    public
    void test_readU16_basic() throws WireParseException {
        int v1 = m_di.readU16();
        assertEquals(2, m_di.readIndex());
        assertEquals(8, m_di.remaining());
        assertEquals(1, v1);

        m_di.jump(1);
        v1 = m_di.readU16();
        assertEquals(258, v1);
    }

    public
    void test_readU16_maxval() throws WireParseException {
        m_di.jump(8);
        int v = m_di.readU16();
        assertEquals(10, m_di.readIndex());
        assertEquals(0, m_di.remaining());
        assertEquals(0xFFFF, v);

        try {
            m_di.jump(9);
            m_di.readU16();
            fail("WireParseException not thrown");
        } catch (WireParseException e) {
            // pass
        }
    }

    public
    void test_readU32_basic() throws WireParseException {
        long v1 = m_di.readU32();
        assertEquals(4, m_di.readIndex());
        assertEquals(6, m_di.remaining());
        assertEquals(66051, v1);
    }

    public
    void test_readU32_maxval() throws WireParseException {
        m_di.jump(6);
        long v = m_di.readU32();
        assertEquals(10, m_di.readIndex());
        assertEquals(0, m_di.remaining());
        assertEquals(0xFFFFFFFFL, v);

        try {
            m_di.jump(7);
            m_di.readU32();
            fail("WireParseException not thrown");
        } catch (WireParseException e) {
            // pass
        }
    }

    public
    void test_readByteArray_0arg() throws WireParseException {
        m_di.jump(1);
        byte[] out = m_di.readByteArray();
        assertEquals(10, m_di.readIndex());
        assertEquals(0, m_di.remaining());
        assertEquals(9, out.length);
        for (int i = 0; i < 9; ++i) {
            assertEquals(m_raw[i + 1], out[i]);
        }
    }

    public
    void test_readByteArray_0arg_boundary() throws WireParseException {
        m_di.jump(9);
        m_di.readU8();
        byte[] out = m_di.readByteArray();
        assertEquals(0, out.length);
    }

    public
    void test_readByteArray_1arg() throws WireParseException {
        byte[] out = m_di.readByteArray(2);
        assertEquals(2, m_di.readIndex());
        assertEquals(8, m_di.remaining());
        assertEquals(2, out.length);
        assertEquals(0, out[0]);
        assertEquals(1, out[1]);
    }

    public
    void test_readByteArray_1arg_boundary() throws WireParseException {
        byte[] out = m_di.readByteArray(10);
        assertEquals(10, m_di.readIndex());
        assertEquals(0, m_di.remaining());
        assertEquals(m_raw, out);
    }

    private
    void assertEquals(byte[] exp, byte[] act) {
        assertTrue(Arrays.equals(exp, act));
    }

    public
    void test_readByteArray_1arg_invalid() {
        try {
            m_di.readByteArray(11);
            fail("WireParseException not thrown");
        } catch (WireParseException e) {
            // pass
        }
    }

    public
    void test_readByteArray_3arg() throws WireParseException {
        byte[] data = new byte[5];
        m_di.jump(4);

        m_di.readByteArray(data, 1, 4);
        assertEquals(8, m_di.readIndex());
        assertEquals(0, data[0]);
        for (int i = 0; i < 4; ++i) {
            assertEquals(m_raw[i + 4], data[i + 1]);
        }
    }

    public
    void test_readCountedSting() throws WireParseException {
        m_di.jump(1);
        byte[] out = m_di.readCountedString();
        assertEquals(1, out.length);
        assertEquals(3, m_di.readIndex());
        assertEquals(out[0], 2);
    }
}
