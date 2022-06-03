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

import dorkbox.dns.dns.utils.Options
import dorkbox.dns.dns.utils.Options.check
import dorkbox.dns.dns.utils.Options.clear
import dorkbox.dns.dns.utils.Options.intValue
import dorkbox.dns.dns.utils.Options.refresh
import dorkbox.dns.dns.utils.Options.set
import dorkbox.dns.dns.utils.Options.unset
import dorkbox.dns.dns.utils.Options.value
import junit.framework.TestCase

class OptionsTest : TestCase() {
    public override fun setUp() {
        // reset the options table before each test
        clear()
    }

    fun test_set_1arg() {
        set("Option1")
        assertEquals("true", value("option1"))

        set("OPTION2")
        assertEquals("true", value("option1"))
        assertEquals("true", value("OpTIOn2"))

        set("option2")
        assertEquals("true", value("option2"))
    }

    fun test_set_2arg() {
        Options["OPTION1"] = "Value1"
        assertEquals("value1", value("Option1"))

        Options["option2"] = "value2"
        assertEquals("value1", value("Option1"))
        assertEquals("value2", value("OPTION2"))

        Options["OPTION2"] = "value2b"
        assertEquals("value1", value("Option1"))
        assertEquals("value2b", value("option2"))
    }

    fun test_check() {
        assertFalse(check("No Options yet"))

        set("First Option")
        assertFalse(check("Not a valid option name"))
        assertTrue(check("First Option"))
        assertTrue(check("FIRST option"))
    }

    fun test_unset() {
        // unset something non-existant
        unset("Not an option Name")
        set("Temporary Option")
        assertTrue(check("Temporary Option"))

        unset("Temporary Option")
        assertFalse(check("Temporary Option"))

        set("Temporary Option")
        assertTrue(check("Temporary Option"))

        unset("temporary option")
        assertFalse(check("Temporary Option"))

        // unset something now that the table is non-null
        unset("Still Not an Option Name")
    }

    fun test_value() {
        assertNull(value("Table is Null"))

        set("Testing Option")
        assertNull(value("Not an Option Name"))
        assertEquals("true", value("Testing OPTION"))
    }

    fun test_intValue() {
        assertEquals(-1, intValue("Table is Null"))

        set("A Boolean Option")
        Options["An Int Option"] = "13"
        Options["Not An Int Option"] = "NotAnInt"
        Options["A Negative Int Value"] = "-1000"
        assertEquals(-1, intValue("A Boolean Option"))
        assertEquals(-1, intValue("Not an Option NAME"))
        assertEquals(13, intValue("an int option"))
        assertEquals(-1, intValue("NOT an INT option"))
        assertEquals(-1, intValue("A negative int Value"))
    }

    fun test_systemProperty() {
        System.setProperty("dnsjava.options", "booleanOption,valuedOption1=10,valuedOption2=NotAnInteger")
        refresh()

        assertTrue(check("booleanOPTION"))
        assertTrue(check("booleanOption"))
        assertTrue(check("valuedOption1"))
        assertTrue(check("ValuedOption2"))
        assertEquals("true", value("booleanOption"))
        assertEquals(-1, intValue("BOOLEANOPTION"))
        assertEquals("10", value("valuedOption1"))
        assertEquals(10, intValue("valuedOption1"))
        assertEquals("notaninteger", value("VALUEDOPTION2"))
        assertEquals(-1, intValue("valuedOption2"))
    }
}
