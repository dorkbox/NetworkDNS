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
package dorkbox.dns.dns.records

import dorkbox.dns.dns.DnsInput
import dorkbox.dns.dns.DnsOutput
import dorkbox.dns.dns.constants.DnsOpCode
import dorkbox.dns.dns.constants.DnsResponseCode
import dorkbox.dns.dns.constants.Flags
import dorkbox.dns.dns.constants.Flags.Companion.toFlag
import junit.framework.TestCase
import java.io.IOException

class HeaderTest : TestCase() {
    private var m_h: Header? = null
    public override fun setUp() {
        m_h = Header(0xABCD) // 43981
    }

    fun test_fixture_state() {
        assertEquals(0xABCD, m_h!!.iD)
        val flags = m_h!!.getFlags()
        for (i in flags.indices) {
            assertFalse(flags[i])
        }
        assertEquals(0, m_h!!.rcode)
        assertEquals(0, m_h!!.opcode)
        assertEquals(0, m_h!!.getCount(0))
        assertEquals(0, m_h!!.getCount(1))
        assertEquals(0, m_h!!.getCount(2))
        assertEquals(0, m_h!!.getCount(3))
    }

    fun test_ctor_0arg() {
        m_h = Header()
        assertTrue(0 <= m_h!!.iD && m_h!!.iD < 0xFFFF)
        val flags = m_h!!.getFlags()
        for (i in flags.indices) {
            assertFalse(flags[i])
        }
        assertEquals(0, m_h!!.rcode)
        assertEquals(0, m_h!!.opcode)
        assertEquals(0, m_h!!.getCount(0))
        assertEquals(0, m_h!!.getCount(1))
        assertEquals(0, m_h!!.getCount(2))
        assertEquals(0, m_h!!.getCount(3))
    }

    @Throws(IOException::class)
    fun test_ctor_DNSInput() {
        val raw = byteArrayOf(
            0x12.toByte(),
            0xAB.toByte(),
            0x8F.toByte(),
            0xBD.toByte(),
            0x65.toByte(),
            0x1C.toByte(),
            0x10.toByte(),
            0xF0.toByte(),
            0x98.toByte(),
            0xBA.toByte(),
            0x71.toByte(),
            0x90.toByte()
        ) // ARCOUNT
        m_h = Header(DnsInput(raw))
        assertEquals(0x12AB, m_h!!.iD)
        val flags = m_h!!.getFlags()
        assertTrue(flags[0])
        assertEquals(1, m_h!!.opcode)
        assertTrue(flags[5])
        assertTrue(flags[6])
        assertTrue(flags[7])
        assertTrue(flags[8])
        assertFalse(flags[9])
        assertTrue(flags[10])
        assertTrue(flags[11])
        assertEquals(0xD, m_h!!.rcode)
        assertEquals(0x651C, m_h!!.getCount(0))
        assertEquals(0x10F0, m_h!!.getCount(1))
        assertEquals(0x98BA, m_h!!.getCount(2))
        assertEquals(0x7190, m_h!!.getCount(3))
    }

    @Throws(IOException::class)
    fun test_toWire() {
        val raw = byteArrayOf(
            0x12.toByte(),
            0xAB.toByte(),
            0x8F.toByte(),
            0xBD.toByte(),
            0x65.toByte(),
            0x1C.toByte(),
            0x10.toByte(),
            0xF0.toByte(),
            0x98.toByte(),
            0xBA.toByte(),
            0x71.toByte(),
            0x90.toByte()
        ) // ARCOUNT
        m_h = Header(raw)
        val dout = DnsOutput()
        m_h!!.toWire(dout)
        var out = dout.toByteArray()
        assertEquals(12, out.size)
        for (i in out.indices) {
            assertEquals(raw[i], out[i])
        }
        m_h!!.opcode = 0xA // 1010
        assertEquals(0xA, m_h!!.opcode)
        m_h!!.rcode = 0x7 // 0111

        // flags is now: 1101 0111 1011 0111
        raw[2] = 0xD7.toByte()
        raw[3] = 0xB7.toByte()
        out = m_h!!.toWire()
        assertEquals(12, out.size)
        for (i in out.indices) {
            assertEquals("i=$i", raw[i], out[i])
        }
    }

    fun test_flags() {
        m_h!!.setFlag(toFlag(0))
        m_h!!.setFlag(toFlag(5))
        assertTrue(m_h!!.getFlag(toFlag(0)))
        assertTrue(m_h!!.getFlags()[0])
        assertTrue(m_h!!.getFlag(toFlag(5)))
        assertTrue(m_h!!.getFlags()[5])
        m_h!!.unsetFlag(toFlag(0))
        assertFalse(m_h!!.getFlag(toFlag(0)))
        assertFalse(m_h!!.getFlags()[0])
        assertTrue(m_h!!.getFlag(toFlag(5)))
        assertTrue(m_h!!.getFlags()[5])
        m_h!!.unsetFlag(toFlag(5))
        assertFalse(m_h!!.getFlag(toFlag(0)))
        assertFalse(m_h!!.getFlags()[0])
        assertFalse(m_h!!.getFlag(toFlag(5)))
        assertFalse(m_h!!.getFlags()[5])
        val flags = m_h!!.getFlags()
        for (i in flags.indices) {
            if (i > 0 && i < 5 || i > 11) {
                continue
            }
            assertFalse(flags[i])
        }
    }

    fun test_flags_invalid() {
        try {
            m_h!!.setFlag(toFlag(-1))
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
        }
        try {
            m_h!!.setFlag(toFlag(1))
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
        }
        try {
            m_h!!.setFlag(toFlag(16))
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
        }
        try {
            m_h!!.unsetFlag(toFlag(-1))
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
        }
        try {
            m_h!!.unsetFlag(toFlag(13))
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
        }
        try {
            m_h!!.unsetFlag(toFlag(16))
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
        }
        try {
            m_h!!.getFlag(toFlag(-1))
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
        }
        try {
            m_h!!.getFlag(toFlag(4))
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
        }
        try {
            m_h!!.getFlag(toFlag(16))
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
        }
    }

    fun test_ID() {
        assertEquals(0xABCD, m_h!!.iD)
        m_h = Header()
        val id = m_h!!.iD
        assertEquals(id, m_h!!.iD)
        assertTrue(id >= 0 && id < 0xffff)
        m_h!!.iD = 0xDCBA
        assertEquals(0xDCBA, m_h!!.iD)
    }

    fun test_setID_invalid() {
        try {
            m_h!!.iD = 0x10000
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
        }
        try {
            m_h!!.iD = -1
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
        }
    }

    fun test_Rcode() {
        assertEquals(0, m_h!!.rcode)
        m_h!!.rcode = 0xA // 1010
        assertEquals(0xA, m_h!!.rcode)
        for (i in 0..11) {
            if (i > 0 && i < 5 || i > 11) {
                continue
            }
            assertFalse(m_h!!.getFlag(toFlag(i)))
        }
    }

    fun test_setRcode_invalid() {
        try {
            m_h!!.rcode = -1
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
        }
        try {
            m_h!!.rcode = 0x100
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
        }
    }

    fun test_Opcode() {
        assertEquals(0, m_h!!.opcode)
        m_h!!.opcode = 0xE // 1110
        assertEquals(0xE, m_h!!.opcode)
        assertFalse(m_h!!.getFlag(toFlag(0)))
        for (i in 5..11) {
            assertFalse(m_h!!.getFlag(toFlag(i)))
        }
        assertEquals(0, m_h!!.rcode)
    }

    fun test_setOpcode_invalid() {
        try {
            m_h!!.opcode = -1
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
        }
        try {
            m_h!!.opcode = 0x100
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
        }
    }

    fun test_Count() {
        m_h!!.setCount(2, 0x1E)
        assertEquals(0, m_h!!.getCount(0))
        assertEquals(0, m_h!!.getCount(1))
        assertEquals(0x1E, m_h!!.getCount(2))
        assertEquals(0, m_h!!.getCount(3))
        m_h!!.incCount(0)
        assertEquals(1, m_h!!.getCount(0))
        m_h!!.decCount(2)
        assertEquals(0x1E - 1, m_h!!.getCount(2))
    }

    fun test_setCount_invalid() {
        try {
            m_h!!.setCount(-1, 0)
            fail("ArrayIndexOutOfBoundsException not thrown")
        } catch (e: ArrayIndexOutOfBoundsException) {
        }
        try {
            m_h!!.setCount(4, 0)
            fail("ArrayIndexOutOfBoundsException not thrown")
        } catch (e: ArrayIndexOutOfBoundsException) {
        }
        try {
            m_h!!.setCount(0, -1)
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
        }
        try {
            m_h!!.setCount(3, 0x10000)
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
        }
    }

    fun test_getCount_invalid() {
        try {
            m_h!!.getCount(-1)
            fail("ArrayIndexOutOfBoundsException not thrown")
        } catch (e: ArrayIndexOutOfBoundsException) {
        }
        try {
            m_h!!.getCount(4)
            fail("ArrayIndexOutOfBoundsException not thrown")
        } catch (e: ArrayIndexOutOfBoundsException) {
        }
    }

    fun test_incCount_invalid() {
        m_h!!.setCount(1, 0xFFFF)
        try {
            m_h!!.incCount(1)
            fail("IllegalStateException not thrown")
        } catch (e: IllegalStateException) {
        }
    }

    fun test_decCount_invalid() {
        m_h!!.setCount(2, 0)
        try {
            m_h!!.decCount(2)
            fail("IllegalStateException not thrown")
        } catch (e: IllegalStateException) {
        }
    }

    fun test_toString() {
        m_h!!.opcode = DnsOpCode.STATUS
        m_h!!.rcode = DnsResponseCode.NXDOMAIN
        m_h!!.setFlag(Flags.QR) // qr
        m_h!!.setFlag(Flags.RD) // rd
        m_h!!.setFlag(Flags.RA) // ra
        m_h!!.setFlag(Flags.CD) // cd
        m_h!!.setCount(1, 0xFF)
        m_h!!.setCount(2, 0x0A)
        val text = m_h.toString()
        assertFalse(text.indexOf("id: 43981") == -1)
        assertFalse(text.indexOf("opcode: STATUS") == -1)
        assertFalse(text.indexOf("status: NXDOMAIN") == -1)
        assertFalse(text.indexOf(" qr ") == -1)
        assertFalse(text.indexOf(" rd ") == -1)
        assertFalse(text.indexOf(" ra ") == -1)
        assertFalse(text.indexOf(" cd ") == -1)
        assertFalse(text.indexOf("qd: 0 ") == -1)
        assertFalse(text.indexOf("an: 255 ") == -1)
        assertFalse(text.indexOf("au: 10 ") == -1)
        assertFalse(text.indexOf("ad: 0 ") == -1)
    }

    fun test_clone() {
        m_h!!.opcode = DnsOpCode.IQUERY
        m_h!!.rcode = DnsResponseCode.SERVFAIL
        m_h!!.setFlag(Flags.QR) // qr
        m_h!!.setFlag(Flags.RD) // rd
        m_h!!.setFlag(Flags.RA) // ra
        m_h!!.setFlag(Flags.CD) // cd
        m_h!!.setCount(1, 0xFF)
        m_h!!.setCount(2, 0x0A)
        val h2 = m_h!!.clone() as Header
        assertNotSame(m_h, h2)
        assertEquals(m_h!!.iD, h2.iD)
        for (i in 0..15) {
            if (i > 0 && i < 5 || i > 11) {
                continue
            }
            assertEquals(m_h!!.getFlag(toFlag(i)), h2.getFlag(toFlag(i)))
        }
        for (i in 0..3) {
            assertEquals(m_h!!.getCount(i), h2.getCount(i))
        }
    }
}
