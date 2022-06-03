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

import dorkbox.dns.dns.Mnemonic
import junit.framework.TestCase
import java.util.*

// Mnemonic has package-level access.
class MnemonicTest(name: String?) : TestCase(name) {
    private var m_mn: Mnemonic? = null
    public override fun setUp() {
        m_mn = Mnemonic(MnemonicTest::class.java.name + " UPPER", Mnemonic.CASE_UPPER)
    }

    fun test_no_maximum() {
        try {
            m_mn!!.check(-1)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
        try {
            m_mn!!.check(0)
        } catch (e: IllegalArgumentException) {
            fail(e.message)
        }
        try {
            m_mn!!.check(Int.MAX_VALUE)
        } catch (e: IllegalArgumentException) {
            fail(e.message)
        }
        m_mn!!.setNumericAllowed(true)
        var `val` = m_mn!!.getValue("-2")
        assertEquals(-1, `val`)
        `val` = m_mn!!.getValue("0")
        assertEquals(0, `val`)
        `val` = m_mn!!.getValue("" + Int.MAX_VALUE)
        assertEquals(Int.MAX_VALUE, `val`)
    }

    fun test_setMaximum() {
        m_mn!!.setMaximum(15)
        try {
            m_mn!!.check(-1)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
        try {
            m_mn!!.check(0)
        } catch (e: IllegalArgumentException) {
            fail(e.message)
        }
        try {
            m_mn!!.check(15)
        } catch (e: IllegalArgumentException) {
            fail(e.message)
        }
        try {
            m_mn!!.check(16)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }

        // need numericok to exercise the usage of max in parseNumeric
        m_mn!!.setNumericAllowed(true)
        var `val` = m_mn!!.getValue("-2")
        assertEquals(-1, `val`)
        `val` = m_mn!!.getValue("0")
        assertEquals(0, `val`)
        `val` = m_mn!!.getValue("15")
        assertEquals(15, `val`)
        `val` = m_mn!!.getValue("16")
        assertEquals(-1, `val`)
    }

    fun test_setPrefix() {
        val prefix = "A mixed CASE Prefix".uppercase(Locale.getDefault())
        m_mn!!.setPrefix(prefix)
        val out = m_mn!!.getText(10)
        assertEquals(prefix + "10", out)
        val i = m_mn!!.getValue(out)
        assertEquals(10, i)
    }

    fun test_basic_operation() {
        // setUp creates Mnemonic with CASE_UPPER
        m_mn!!.add(10, "Ten")
        m_mn!!.add(20, "Twenty")
        m_mn!!.addAlias(20, "Veinte")
        m_mn!!.add(30, "Thirty")
        var text = m_mn!!.getText(10)
        assertEquals("TEN", text)
        text = m_mn!!.getText(20)
        assertEquals("TWENTY", text)
        text = m_mn!!.getText(30)
        assertEquals("THIRTY", text)
        text = m_mn!!.getText(40)
        assertEquals("40", text)
        var value = m_mn!!.getValue("tEn")
        assertEquals(10, value)
        value = m_mn!!.getValue("twenty")
        assertEquals(20, value)
        value = m_mn!!.getValue("VeiNTe")
        assertEquals(20, value)
        value = m_mn!!.getValue("THIRTY")
        assertEquals(30, value)
    }

    fun test_basic_operation_lower() {
        m_mn = Mnemonic(MnemonicTest::class.java.name + " LOWER", Mnemonic.CASE_LOWER)
        m_mn!!.add(10, "Ten")
        m_mn!!.add(20, "Twenty")
        m_mn!!.addAlias(20, "Veinte")
        m_mn!!.add(30, "Thirty")
        var text = m_mn!!.getText(10)
        assertEquals("ten", text)
        text = m_mn!!.getText(20)
        assertEquals("twenty", text)
        text = m_mn!!.getText(30)
        assertEquals("thirty", text)
        text = m_mn!!.getText(40)
        assertEquals("40", text)
        var value = m_mn!!.getValue("tEn")
        assertEquals(10, value)
        value = m_mn!!.getValue("twenty")
        assertEquals(20, value)
        value = m_mn!!.getValue("VeiNTe")
        assertEquals(20, value)
        value = m_mn!!.getValue("THIRTY")
        assertEquals(30, value)
    }

    fun test_basic_operation_sensitive() {
        m_mn = Mnemonic(MnemonicTest::class.java.name + " SENSITIVE", Mnemonic.CASE_SENSITIVE)
        m_mn!!.add(10, "Ten")
        m_mn!!.add(20, "Twenty")
        m_mn!!.addAlias(20, "Veinte")
        m_mn!!.add(30, "Thirty")
        var text = m_mn!!.getText(10)
        assertEquals("Ten", text)
        text = m_mn!!.getText(20)
        assertEquals("Twenty", text)
        text = m_mn!!.getText(30)
        assertEquals("Thirty", text)
        text = m_mn!!.getText(40)
        assertEquals("40", text)
        var value = m_mn!!.getValue("Ten")
        assertEquals(10, value)
        value = m_mn!!.getValue("twenty")
        assertEquals(-1, value)
        value = m_mn!!.getValue("Twenty")
        assertEquals(20, value)
        value = m_mn!!.getValue("VEINTE")
        assertEquals(-1, value)
        value = m_mn!!.getValue("Veinte")
        assertEquals(20, value)
        value = m_mn!!.getValue("Thirty")
        assertEquals(30, value)
    }

    fun test_invalid_numeric() {
        m_mn!!.setNumericAllowed(true)
        val value = m_mn!!.getValue("Not-A-Number")
        assertEquals(-1, value)
    }

    fun test_addAll() {
        m_mn!!.add(10, "Ten")
        m_mn!!.add(20, "Twenty")
        val mn2 = Mnemonic("second test Mnemonic", Mnemonic.CASE_UPPER)
        mn2.add(20, "Twenty")
        mn2.addAlias(20, "Veinte")
        mn2.add(30, "Thirty")
        m_mn!!.addAll(mn2)
        var text = m_mn!!.getText(10)
        assertEquals("TEN", text)
        text = m_mn!!.getText(20)
        assertEquals("TWENTY", text)
        text = m_mn!!.getText(30)
        assertEquals("THIRTY", text)
        text = m_mn!!.getText(40)
        assertEquals("40", text)
        var value = m_mn!!.getValue("tEn")
        assertEquals(10, value)
        value = m_mn!!.getValue("twenty")
        assertEquals(20, value)
        value = m_mn!!.getValue("VeiNTe")
        assertEquals(20, value)
        value = m_mn!!.getValue("THIRTY")
        assertEquals(30, value)
    }
}
