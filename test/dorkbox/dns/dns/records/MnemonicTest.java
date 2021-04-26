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

// Mnemonic has package-level access.

import dorkbox.dns.dns.Mnemonic;
import junit.framework.TestCase;

public
class MnemonicTest extends TestCase {
    private Mnemonic m_mn;

    public
    MnemonicTest(String name) {
        super(name);
    }

    @Override
    public
    void setUp() {
        m_mn = new Mnemonic(MnemonicTest.class.getName() + " UPPER", Mnemonic.CASE_UPPER);
    }

    public
    void test_no_maximum() {
        try {
            m_mn.check(-1);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException ignored) {
        }
        try {
            m_mn.check(0);
        } catch (IllegalArgumentException e) {
            fail(e.getMessage());
        }
        try {
            m_mn.check(Integer.MAX_VALUE);
        } catch (IllegalArgumentException e) {
            fail(e.getMessage());
        }

        m_mn.setNumericAllowed(true);

        int val = m_mn.getValue("-2");
        assertEquals(-1, val);

        val = m_mn.getValue("0");
        assertEquals(0, val);

        val = m_mn.getValue("" + Integer.MAX_VALUE);
        assertEquals(Integer.MAX_VALUE, val);
    }

    public
    void test_setMaximum() {
        m_mn.setMaximum(15);
        try {
            m_mn.check(-1);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException ignored) {
        }
        try {
            m_mn.check(0);
        } catch (IllegalArgumentException e) {
            fail(e.getMessage());
        }
        try {
            m_mn.check(15);
        } catch (IllegalArgumentException e) {
            fail(e.getMessage());
        }
        try {
            m_mn.check(16);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException ignored) {
        }

        // need numericok to exercise the usage of max in parseNumeric
        m_mn.setNumericAllowed(true);

        int val = m_mn.getValue("-2");
        assertEquals(-1, val);

        val = m_mn.getValue("0");
        assertEquals(0, val);

        val = m_mn.getValue("15");
        assertEquals(15, val);

        val = m_mn.getValue("16");
        assertEquals(-1, val);
    }

    public
    void test_setPrefix() {
        final String prefix = "A mixed CASE Prefix".toUpperCase();
        m_mn.setPrefix(prefix);

        String out = m_mn.getText(10);
        assertEquals(prefix + "10", out);

        int i = m_mn.getValue(out);
        assertEquals(10, i);
    }

    public
    void test_basic_operation() {
        // setUp creates Mnemonic with CASE_UPPER
        m_mn.add(10, "Ten");
        m_mn.add(20, "Twenty");
        m_mn.addAlias(20, "Veinte");
        m_mn.add(30, "Thirty");

        String text = m_mn.getText(10);
        assertEquals("TEN", text);

        text = m_mn.getText(20);
        assertEquals("TWENTY", text);

        text = m_mn.getText(30);
        assertEquals("THIRTY", text);

        text = m_mn.getText(40);
        assertEquals("40", text);

        int value = m_mn.getValue("tEn");
        assertEquals(10, value);

        value = m_mn.getValue("twenty");
        assertEquals(20, value);

        value = m_mn.getValue("VeiNTe");
        assertEquals(20, value);

        value = m_mn.getValue("THIRTY");
        assertEquals(30, value);
    }

    public
    void test_basic_operation_lower() {
        m_mn = new Mnemonic(MnemonicTest.class.getName() + " LOWER", Mnemonic.CASE_LOWER);
        m_mn.add(10, "Ten");
        m_mn.add(20, "Twenty");
        m_mn.addAlias(20, "Veinte");
        m_mn.add(30, "Thirty");

        String text = m_mn.getText(10);
        assertEquals("ten", text);

        text = m_mn.getText(20);
        assertEquals("twenty", text);

        text = m_mn.getText(30);
        assertEquals("thirty", text);

        text = m_mn.getText(40);
        assertEquals("40", text);

        int value = m_mn.getValue("tEn");
        assertEquals(10, value);

        value = m_mn.getValue("twenty");
        assertEquals(20, value);

        value = m_mn.getValue("VeiNTe");
        assertEquals(20, value);

        value = m_mn.getValue("THIRTY");
        assertEquals(30, value);
    }

    public
    void test_basic_operation_sensitive() {
        m_mn = new Mnemonic(MnemonicTest.class.getName() + " SENSITIVE", Mnemonic.CASE_SENSITIVE);
        m_mn.add(10, "Ten");
        m_mn.add(20, "Twenty");
        m_mn.addAlias(20, "Veinte");
        m_mn.add(30, "Thirty");

        String text = m_mn.getText(10);
        assertEquals("Ten", text);

        text = m_mn.getText(20);
        assertEquals("Twenty", text);

        text = m_mn.getText(30);
        assertEquals("Thirty", text);

        text = m_mn.getText(40);
        assertEquals("40", text);

        int value = m_mn.getValue("Ten");
        assertEquals(10, value);

        value = m_mn.getValue("twenty");
        assertEquals(-1, value);

        value = m_mn.getValue("Twenty");
        assertEquals(20, value);

        value = m_mn.getValue("VEINTE");
        assertEquals(-1, value);

        value = m_mn.getValue("Veinte");
        assertEquals(20, value);

        value = m_mn.getValue("Thirty");
        assertEquals(30, value);
    }

    public
    void test_invalid_numeric() {
        m_mn.setNumericAllowed(true);
        int value = m_mn.getValue("Not-A-Number");
        assertEquals(-1, value);
    }

    public
    void test_addAll() {
        m_mn.add(10, "Ten");
        m_mn.add(20, "Twenty");

        Mnemonic mn2 = new Mnemonic("second test Mnemonic", Mnemonic.CASE_UPPER);
        mn2.add(20, "Twenty");
        mn2.addAlias(20, "Veinte");
        mn2.add(30, "Thirty");

        m_mn.addAll(mn2);

        String text = m_mn.getText(10);
        assertEquals("TEN", text);

        text = m_mn.getText(20);
        assertEquals("TWENTY", text);

        text = m_mn.getText(30);
        assertEquals("THIRTY", text);

        text = m_mn.getText(40);
        assertEquals("40", text);

        int value = m_mn.getValue("tEn");
        assertEquals(10, value);

        value = m_mn.getValue("twenty");
        assertEquals(20, value);

        value = m_mn.getValue("VeiNTe");
        assertEquals(20, value);

        value = m_mn.getValue("THIRTY");
        assertEquals(30, value);
    }
}
