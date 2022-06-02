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
 * Constants and functions relating to EDNS flags.
 *
 * @author Brian Wellington
 */
enum class ExtendedFlags(flagValue: Int, textValue: String) {
    /**
     * dnssec ok
     */
    DO(0x8000, "do");

    private val flagValue: Byte
    private val textValue: String

    init {
        this.flagValue = flagValue.toByte()
        this.textValue = textValue
    }

    fun value(): Byte {
        return flagValue
    }

    fun string(): String {
        return textValue
    }

    companion object {
        private val extflags = Mnemonic("EDNS Flag", Mnemonic.CASE_LOWER)

        init {
            extflags.setMaximum(0xFFFF)
            extflags.setPrefix("FLAG")
            extflags.setNumericAllowed(true)
            extflags.add(DO.flagValue.toInt(), "do")
        }

        /**
         * Converts a numeric extended flag into a String
         */
        fun string(i: Int): String {
            return extflags.getText(i)
        }

        /**
         * Converts a textual representation of an extended flag into its numeric
         * value
         */
        fun value(s: String): Int {
            return extflags.getValue(s)
        }
    }
}
