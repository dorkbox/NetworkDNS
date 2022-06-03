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

import dorkbox.dns.dns.DnsOutput
import junit.framework.TestCase
import java.util.*

class DNSOutputTest : TestCase() {
    private var m_do: DnsOutput? = null
    public override fun setUp() {
        m_do = DnsOutput(1)
    }

    fun test_default_ctor() {
        m_do = DnsOutput()
        assertEquals(0, m_do!!.current())
    }

    fun test_initial_state() {
        assertEquals(0, m_do!!.current())
        try {
            m_do!!.restore()
            fail("IllegalStateException not thrown")
        } catch (e: IllegalStateException) {
            // pass
        }
        try {
            m_do!!.jump(1)
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
            // pass
        }
    }

    fun test_writeU8_basic() {
        m_do!!.writeU8(1)
        assertEquals(1, m_do!!.current())
        val curr = m_do!!.toByteArray()
        assertEquals(1, curr.size)
        assertEquals(1, curr[0].toInt())
    }

    fun test_writeU8_expand() {
        // starts off at 1;
        m_do!!.writeU8(1)
        m_do!!.writeU8(2)
        assertEquals(2, m_do!!.current())
        val curr = m_do!!.toByteArray()
        assertEquals(2, curr.size)
        assertEquals(1, curr[0].toInt())
        assertEquals(2, curr[1].toInt())
    }

    fun test_writeU8_max() {
        m_do!!.writeU8(0xFF)
        val curr = m_do!!.toByteArray()
        assertEquals(0xFF.toByte(), curr[0])
    }

    fun test_writeU8_toobig() {
        try {
            m_do!!.writeU8(0x1FF)
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
            // pass
        }
    }

    fun test_writeU16_basic() {
        m_do!!.writeU16(0x100)
        assertEquals(2, m_do!!.current())
        val curr = m_do!!.toByteArray()
        assertEquals(2, curr.size)
        assertEquals(1, curr[0].toInt())
        assertEquals(0, curr[1].toInt())
    }

    fun test_writeU16_max() {
        m_do!!.writeU16(0xFFFF)
        val curr = m_do!!.toByteArray()
        assertEquals(0xFF.toByte(), curr[0])
        assertEquals(0XFF.toByte(), curr[1])
    }

    fun test_writeU16_toobig() {
        try {
            m_do!!.writeU16(0x1FFFF)
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
            // pass
        }
    }

    fun test_writeU32_basic() {
        m_do!!.writeU32(0x11001011)
        assertEquals(4, m_do!!.current())
        val curr = m_do!!.toByteArray()
        assertEquals(4, curr.size)
        assertEquals(0x11, curr[0].toInt())
        assertEquals(0x00, curr[1].toInt())
        assertEquals(0x10, curr[2].toInt())
        assertEquals(0x11, curr[3].toInt())
    }

    fun test_writeU32_max() {
        m_do!!.writeU32(0xFFFFFFFFL)
        val curr = m_do!!.toByteArray()
        assertEquals(0xFF.toByte(), curr[0])
        assertEquals(0XFF.toByte(), curr[1])
        assertEquals(0XFF.toByte(), curr[2])
        assertEquals(0XFF.toByte(), curr[3])
    }

    fun test_writeU32_toobig() {
        try {
            m_do!!.writeU32(0x1FFFFFFFFL)
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
            // pass
        }
    }

    fun test_jump_basic() {
        m_do!!.writeU32(0x11223344L)
        assertEquals(4, m_do!!.current())
        m_do!!.jump(2)
        assertEquals(2, m_do!!.current())
        m_do!!.writeU8(0x99)
        val curr = m_do!!.toByteArray()
        assertEquals(3, curr.size)
        assertEquals(0x11, curr[0].toInt())
        assertEquals(0x22, curr[1].toInt())
        assertEquals(0x99.toByte(), curr[2])
    }

    fun test_writeByteArray_1arg() {
        val `in` = byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte(), 0x12.toByte(), 0x34.toByte())
        m_do!!.writeByteArray(`in`)
        assertEquals(5, m_do!!.current())
        val curr = m_do!!.toByteArray()
        assertEquals(`in`, curr)
    }

    private fun assertEquals(exp: ByteArray, act: ByteArray) {
        assertTrue(Arrays.equals(exp, act))
    }

    fun test_writeByteArray_3arg() {
        val `in` = byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte(), 0x12.toByte(), 0x34.toByte())
        m_do!!.writeByteArray(`in`, 2, 3)
        assertEquals(3, m_do!!.current())
        val exp = byteArrayOf(`in`[2], `in`[3], `in`[4])
        val curr = m_do!!.toByteArray()
        assertEquals(exp, curr)
    }

    fun test_writeCountedString_basic() {
        val `in` = byteArrayOf('h'.code.toByte(), 'e'.code.toByte(), 'l'.code.toByte(), 'L'.code.toByte(), '0'.code.toByte())
        m_do!!.writeCountedString(`in`)
        assertEquals(`in`.size + 1, m_do!!.current())
        val curr = m_do!!.toByteArray()
        val exp = byteArrayOf(`in`.size.toByte(), `in`[0], `in`[1], `in`[2], `in`[3], `in`[4])
        assertEquals(exp, curr)
    }

    fun test_writeCountedString_empty() {
        val `in` = byteArrayOf()
        m_do!!.writeCountedString(`in`)
        assertEquals(`in`.size + 1, m_do!!.current())
        val curr = m_do!!.toByteArray()
        val exp = byteArrayOf(`in`.size.toByte())
        assertEquals(exp, curr)
    }

    fun test_writeCountedString_toobig() {
        val `in` = ByteArray(256)
        try {
            m_do!!.writeCountedString(`in`)
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalArgumentException) {
            // pass
        }
    }

    fun test_save_restore() {
        m_do!!.writeU32(0x12345678L)
        assertEquals(4, m_do!!.current())
        m_do!!.save()
        m_do!!.writeU16(0xABCD)
        assertEquals(6, m_do!!.current())
        m_do!!.restore()
        assertEquals(4, m_do!!.current())
        try {
            m_do!!.restore()
            fail("IllegalArgumentException not thrown")
        } catch (e: IllegalStateException) {
            // pass
        }
    }
}
