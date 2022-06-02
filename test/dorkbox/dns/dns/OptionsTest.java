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

import dorkbox.dns.dns.utils.Options;
import junit.framework.TestCase;

public
class OptionsTest extends TestCase {
    @Override
    public
    void setUp() {
        // reset the options table before each test
        Options.clear();
    }

    public
    void test_set_1arg() {
        Options.INSTANCE.set("Option1");
        assertEquals("true", Options.value("option1"));

        Options.INSTANCE.set("OPTION2");
        assertEquals("true", Options.value("option1"));
        assertEquals("true", Options.value("OpTIOn2"));

        Options.INSTANCE.set("option2");
        assertEquals("true", Options.value("option2"));
    }

    public
    void test_set_2arg() {
        Options.set("OPTION1", "Value1");
        assertEquals("value1", Options.value("Option1"));

        Options.set("option2", "value2");
        assertEquals("value1", Options.value("Option1"));
        assertEquals("value2", Options.value("OPTION2"));

        Options.set("OPTION2", "value2b");
        assertEquals("value1", Options.value("Option1"));
        assertEquals("value2b", Options.value("option2"));
    }

    public
    void test_check() {
        assertFalse(Options.check("No Options yet"));

        Options.INSTANCE.set("First Option");
        assertFalse(Options.check("Not a valid option name"));
        assertTrue(Options.check("First Option"));
        assertTrue(Options.check("FIRST option"));
    }

    public
    void test_unset() {
        // unset something non-existant
        Options.unset("Not an option Name");

        Options.INSTANCE.set("Temporary Option");
        assertTrue(Options.check("Temporary Option"));
        Options.unset("Temporary Option");
        assertFalse(Options.check("Temporary Option"));

        Options.INSTANCE.set("Temporary Option");
        assertTrue(Options.check("Temporary Option"));
        Options.unset("temporary option");
        assertFalse(Options.check("Temporary Option"));

        // unset something now that the table is non-null
        Options.unset("Still Not an Option Name");
    }

    public
    void test_value() {
        assertNull(Options.value("Table is Null"));

        Options.INSTANCE.set("Testing Option");
        assertNull(Options.value("Not an Option Name"));

        assertEquals("true", Options.value("Testing OPTION"));
    }

    public
    void test_intValue() {
        assertEquals(-1, Options.intValue("Table is Null"));

        Options.INSTANCE.set("A Boolean Option");
        Options.set("An Int Option", "13");
        Options.set("Not An Int Option", "NotAnInt");
        Options.set("A Negative Int Value", "-1000");

        assertEquals(-1, Options.intValue("A Boolean Option"));
        assertEquals(-1, Options.intValue("Not an Option NAME"));
        assertEquals(13, Options.intValue("an int option"));
        assertEquals(-1, Options.intValue("NOT an INT option"));
        assertEquals(-1, Options.intValue("A negative int Value"));
    }

    public
    void test_systemProperty() {
        System.setProperty("dnsjava.options", "booleanOption,valuedOption1=10,valuedOption2=NotAnInteger");

        Options.refresh();

        assertTrue(Options.check("booleanOPTION"));
        assertTrue(Options.check("booleanOption"));
        assertTrue(Options.check("valuedOption1"));
        assertTrue(Options.check("ValuedOption2"));

        assertEquals("true", Options.value("booleanOption"));
        assertEquals(-1, Options.intValue("BOOLEANOPTION"));
        assertEquals("10", Options.value("valuedOption1"));
        assertEquals(10, Options.intValue("valuedOption1"));
        assertEquals("notaninteger", Options.value("VALUEDOPTION2"));
        assertEquals(-1, Options.intValue("valuedOption2"));
    }
}
