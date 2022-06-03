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
package dorkbox.dns.dns

import dorkbox.dns.dns.exceptions.WireParseException
import junit.framework.TestCase
import java.util.*

class DNSInputTest : TestCase() {
    private lateinit var m_raw: ByteArray
    private lateinit var m_di: DnsInput

    public override fun setUp() {
        m_raw = byteArrayOf(0, 1, 2, 3, 4, 5, 255.toByte(), 255.toByte(), 255.toByte(), 255.toByte())
        m_di = DnsInput(m_raw)
    }

    fun test_initial_state() {
        assertEquals(0, m_di.readIndex())
        assertEquals(10, m_di.remaining())
    }

    fun test_jump1() {
        m_di.jump(1)
        assertEquals(1, m_di.readIndex())
        assertEquals(9, m_di.remaining())
    }

    fun test_jump2() {
        m_di.jump(9)
        assertEquals(9, m_di.readIndex())
        assertEquals(1, m_di.remaining())
    }

    fun test_jump_invalid() {
        try {
            m_di.jump(10)
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
            // pass
        }
    }

    fun test_setActive() {
        m_di.setActive(5)
        assertEquals(0, m_di.readIndex())
        assertEquals(5, m_di.remaining())
    }

    fun test_setActive_boundary1() {
        m_di.setActive(10)
        assertEquals(0, m_di.readIndex())
        assertEquals(10, m_di.remaining())
    }

    fun test_setActive_boundary2() {
        m_di.setActive(0)
        assertEquals(0, m_di.readIndex())
        assertEquals(0, m_di.remaining())
    }

    fun test_setActive_invalid() {
        try {
            m_di.setActive(11)
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
            // pass
        }
    }

    fun test_clearActive() {
        // first without setting active:
        m_di.restoreActive()
        assertEquals(0, m_di.readIndex())
        assertEquals(10, m_di.remaining())

        m_di.setActive(5)
        m_di.restoreActive()
        assertEquals(0, m_di.readIndex())
        assertEquals(10, m_di.remaining())
    }

    fun test_restore_invalid() {
        try {
            m_di.restore()
            fail("IllegalStateException not thrown")
        } catch (e: IllegalStateException) {
            // pass
        }
    }

    fun test_save_restore() {
        m_di.jump(4)
        assertEquals(4, m_di.readIndex())
        assertEquals(6, m_di.remaining())

        m_di.save()
        m_di.jump(0)
        assertEquals(0, m_di.readIndex())
        assertEquals(10, m_di.remaining())
        m_di.restore()

        assertEquals(4, m_di.readIndex())
        assertEquals(6, m_di.remaining())
    }

    @Throws(WireParseException::class)
    fun test_readU8_basic() {
        val v1 = m_di.readU8()
        assertEquals(1, m_di.readIndex())
        assertEquals(9, m_di.remaining())
        assertEquals(0, v1)
    }

    @Throws(WireParseException::class)
    fun test_readU8_maxval() {
        m_di.jump(9)
        var v1 = m_di.readU8()
        assertEquals(10, m_di.readIndex())
        assertEquals(0, m_di.remaining())
        assertEquals(255, v1)

        try {
            v1 = m_di.readU8()
            fail("WireParseException not thrown")
        } catch (e: WireParseException) {
            // pass
        }
    }

    @Throws(WireParseException::class)
    fun test_readU16_basic() {
        var v1 = m_di.readU16()
        assertEquals(2, m_di.readIndex())
        assertEquals(8, m_di.remaining())
        assertEquals(1, v1)

        m_di.jump(1)
        v1 = m_di.readU16()
        assertEquals(258, v1)
    }

    @Throws(WireParseException::class)
    fun test_readU16_maxval() {
        m_di.jump(8)
        val v = m_di.readU16()
        assertEquals(10, m_di.readIndex())
        assertEquals(0, m_di.remaining())
        assertEquals(0xFFFF, v)

        try {
            m_di.jump(9)
            m_di.readU16()
            fail("WireParseException not thrown")
        } catch (e: WireParseException) {
            // pass
        }
    }

    @Throws(WireParseException::class)
    fun test_readU32_basic() {
        val v1 = m_di.readU32()
        assertEquals(4, m_di.readIndex())
        assertEquals(6, m_di.remaining())
        assertEquals(66051, v1)
    }

    @Throws(WireParseException::class)
    fun test_readU32_maxval() {
        m_di.jump(6)
        val v = m_di.readU32()
        assertEquals(10, m_di.readIndex())
        assertEquals(0, m_di.remaining())
        assertEquals(0xFFFFFFFFL, v)

        try {
            m_di.jump(7)
            m_di.readU32()
            fail("WireParseException not thrown")
        } catch (e: WireParseException) {
            // pass
        }
    }

    @Throws(WireParseException::class)
    fun test_readByteArray_0arg() {
        m_di.jump(1)
        val out = m_di.readByteArray()
        assertEquals(10, m_di.readIndex())
        assertEquals(0, m_di.remaining())
        assertEquals(9, out.size)

        for (i in 0..8) {
            assertEquals(m_raw[i + 1], out[i])
        }
    }

    @Throws(WireParseException::class)
    fun test_readByteArray_0arg_boundary() {
        m_di.jump(9)
        m_di.readU8()

        val out = m_di.readByteArray()
        assertEquals(0, out.size)
    }

    @Throws(WireParseException::class)
    fun test_readByteArray_1arg() {
        val out = m_di.readByteArray(2)
        assertEquals(2, m_di.readIndex())
        assertEquals(8, m_di.remaining())
        assertEquals(2, out.size)
        assertEquals(0, out[0].toInt())
        assertEquals(1, out[1].toInt())
    }

    @Throws(WireParseException::class)
    fun test_readByteArray_1arg_boundary() {
        val out = m_di.readByteArray(10)
        assertEquals(10, m_di.readIndex())
        assertEquals(0, m_di.remaining())
        assertEquals(m_raw, out)
    }

    private fun assertEquals(exp: ByteArray, act: ByteArray) {
        assertTrue(Arrays.equals(exp, act))
    }

    fun test_readByteArray_1arg_invalid() {
        try {
            m_di.readByteArray(11)
            fail("WireParseException not thrown")
        } catch (e: WireParseException) {
            // pass
        }
    }

    @Throws(WireParseException::class)
    fun test_readByteArray_3arg() {
        val data = ByteArray(5)
        m_di.jump(4)
        m_di.readByteArray(data, 1, 4)
        assertEquals(8, m_di.readIndex())
        assertEquals(0, data[0].toInt())

        for (i in 0..3) {
            assertEquals(m_raw[i + 4], data[i + 1])
        }
    }

    @Throws(WireParseException::class)
    fun test_readCountedSting() {
        m_di.jump(1)
        val out = m_di.readCountedString()
        assertEquals(1, out.size)
        assertEquals(3, m_di.readIndex())
        assertEquals(out[0].toInt(), 2)
    }
}
