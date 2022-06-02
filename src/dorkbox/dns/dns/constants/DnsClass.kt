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
package dorkbox.dns.dns.constants

import dorkbox.dns.dns.Mnemonic
import dorkbox.dns.dns.exceptions.InvalidDClassException

/**
 * Constants and functions relating to DNS classes.  This is called DnsClass to avoid confusion with Class.
 *
 * @author Brian Wellington
 */
object DnsClass {
    /**
     * Internet DNS resource record class: `IN`
     */
    const val IN = 1

    /**
     * Computer Science Network network DNS resource record class: `CSNET`. It was never installed as a top-level domain
     * in the Domain Name System, but parsed in the message routing logic of mail transport agents (MTA). It was introduced in 1985.
     */
    const val CS = 2

    /**
     * Computer Science Network network DNS resource record class: `CSNET`. It was never installed as a top-level domain
     * in the Domain Name System, but parsed in the message routing logic of mail transport agents (MTA). It was introduced in 1985.
     */
    const val CSNET = 2

    /**
     * Chaos network DNS resource record class: `CH` (MIT)
     */
    const val CH = 3

    /**
     * Chaos network DNS resource record class: `CHAOS` (MIT, alternate name)
     */
    const val CHAOS = 3

    /**
     * Hesiod DNS resource record class: `HS` (MIT)
     */
    const val HS = 4

    /**
     * Hesiod DNS resource record class: `HESIOD` (MIT, alternate name)
     */
    const val HESIOD = 4

    /**
     * Special value used in dynamic update messages
     */
    const val NONE = 254

    /**
     * Matches any class
     */
    const val ANY = 255
    private val classes: Mnemonic = DClassMnemonic()

    init {
        classes.add(IN, "IN")
        classes.add(CS, "CS")
        classes.addAlias(CSNET, "CSNET")
        classes.add(CH, "CH")
        classes.addAlias(CH, "CHAOS")
        classes.add(HS, "HS")
        classes.addAlias(HS, "HESIOD")
        classes.add(NONE, "NONE")
        classes.add(ANY, "ANY")
    }

    /**
     * Checks that a numeric DnsClass is valid.
     *
     * @throws InvalidDClassException The class is out of range.
     */
    fun check(i: Int) {
        if (i < 0 || i > 0xFFFF) {
            throw InvalidDClassException(i)
        }
    }

    /**
     * Converts a numeric DnsClass into a String
     *
     * @return The canonical string representation of the class
     *
     * @throws InvalidDClassException The class is out of range.
     */
    fun string(i: Int): String {
        return classes.getText(i)
    }

    /**
     * Converts a String representation of a DnsClass into its numeric value
     *
     * @return The class code, or -1 on error.
     */
    fun value(s: String): Int {
        return classes.getValue(s)
    }

    private class DClassMnemonic internal constructor() : Mnemonic("DnsClass", CASE_UPPER) {
        init {
            setPrefix("CLASS")
        }

        override fun check(`val`: Int) {
            DnsClass.check(`val`)
        }
    }
}
