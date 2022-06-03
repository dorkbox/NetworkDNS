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

/**
 * Constants and functions relating to DNS message sections
 *
 * @author Brian Wellington
 */
object DnsSection {
    const val TOTAL_SECTION_COUNT = 4

    /**
     * The question (first) section
     */
    const val QUESTION = 0

    /**
     * The answer (second) section
     */
    const val ANSWER = 1

    /**
     * The authority (third) section
     */
    const val AUTHORITY = 2

    /**
     * The additional (fourth) section
     */
    const val ADDITIONAL = 3
    /* Aliases for dynamic update */
    /**
     * The zone (first) section of a dynamic update message
     */
    const val ZONE = 0

    /**
     * The prerequisite (second) section of a dynamic update message
     */
    const val PREREQ = 1

    /**
     * The update (third) section of a dynamic update message
     */
    const val UPDATE = 2
    private val sections = Mnemonic("DnsMessage DnsSection", Mnemonic.CASE_LOWER)
    private val longSections = arrayOfNulls<String>(4)
    private val updateSections = arrayOfNulls<String>(4)

    init {
        sections.setMaximum(3)
        sections.setNumericAllowed(true)
        sections.add(QUESTION, "qd")
        sections.add(ANSWER, "an")
        sections.add(AUTHORITY, "au")
        sections.add(ADDITIONAL, "ad")
        longSections[QUESTION] = "QUESTIONS"
        longSections[ANSWER] = "ANSWERS"
        longSections[AUTHORITY] = "AUTHORITY RECORDS"
        longSections[ADDITIONAL] = "ADDITIONAL RECORDS"
        updateSections[ZONE] = "ZONE"
        updateSections[PREREQ] = "PREREQUISITES"
        updateSections[UPDATE] = "UPDATE RECORDS"
        updateSections[ADDITIONAL] = "ADDITIONAL RECORDS"
    }

    /**
     * Converts a numeric DnsSection into an abbreviation String
     */
    fun string(i: Int): String {
        return sections.getText(i)
    }

    /**
     * Converts a numeric DnsSection into a full description String
     */
    fun longString(i: Int): String? {
        sections.check(i)
        return longSections[i]
    }

    /**
     * Converts a numeric DnsSection into a full description String for an update
     * DnsMessage.
     */
    fun updString(i: Int): String? {
        sections.check(i)
        return updateSections[i]
    }

    /**
     * Converts a String representation of a DnsSection into its numeric value
     */
    fun value(s: String?): Int {
        return sections.getValue(s!!)
    }
}
