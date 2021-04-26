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

package dorkbox.dns.dns.constants;

import dorkbox.dns.dns.Mnemonic;

/**
 * Constants and functions relating to DNS message sections
 *
 * @author Brian Wellington
 */

public final
class DnsSection {
    public static final int TOTAL_SECTION_COUNT = 4;

    /**
     * The question (first) section
     */
    public static final int QUESTION = 0;

    /**
     * The answer (second) section
     */
    public static final int ANSWER = 1;

    /**
     * The authority (third) section
     */
    public static final int AUTHORITY = 2;

    /**
     * The additional (fourth) section
     */
    public static final int ADDITIONAL = 3;

/* Aliases for dynamic update */
    /**
     * The zone (first) section of a dynamic update message
     */
    public static final int ZONE = 0;

    /**
     * The prerequisite (second) section of a dynamic update message
     */
    public static final int PREREQ = 1;

    /**
     * The update (third) section of a dynamic update message
     */
    public static final int UPDATE = 2;

    private static Mnemonic sections = new Mnemonic("DnsMessage DnsSection", Mnemonic.CASE_LOWER);
    private static String[] longSections = new String[4];
    private static String[] updateSections = new String[4];

    static {
        sections.setMaximum(3);
        sections.setNumericAllowed(true);

        sections.add(QUESTION, "qd");
        sections.add(ANSWER, "an");
        sections.add(AUTHORITY, "au");
        sections.add(ADDITIONAL, "ad");

        longSections[QUESTION] = "QUESTIONS";
        longSections[ANSWER] = "ANSWERS";
        longSections[AUTHORITY] = "AUTHORITY RECORDS";
        longSections[ADDITIONAL] = "ADDITIONAL RECORDS";

        updateSections[ZONE] = "ZONE";
        updateSections[PREREQ] = "PREREQUISITES";
        updateSections[UPDATE] = "UPDATE RECORDS";
        updateSections[ADDITIONAL] = "ADDITIONAL RECORDS";
    }

    private
    DnsSection() {}

    /**
     * Converts a numeric DnsSection into an abbreviation String
     */
    public static
    String string(int i) {
        return sections.getText(i);
    }

    /**
     * Converts a numeric DnsSection into a full description String
     */
    public static
    String longString(int i) {
        sections.check(i);
        return longSections[i];
    }

    /**
     * Converts a numeric DnsSection into a full description String for an update
     * DnsMessage.
     */
    public static
    String updString(int i) {
        sections.check(i);
        return updateSections[i];
    }

    /**
     * Converts a String representation of a DnsSection into its numeric value
     */
    public static
    int value(String s) {
        return sections.getValue(s);
    }

}
