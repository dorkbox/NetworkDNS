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

import dorkbox.collections.IntMap
import dorkbox.collections.ObjectIntMap
import java.util.*

/**
 * A utility class for converting between numeric codes and mnemonics
 * for those codes.  Mnemonics are case insensitive.
 *
 * @author Brian Wellington
 */
open class Mnemonic(private val description: String, private val wordcase: Int) {
    private val strings: ObjectIntMap<String>
    private val values: IntMap<String>
    private var prefix: String? = null
    private var max: Int
    private var numericok = false

    /**
     * Creates a new Mnemonic table.
     *
     * @param description A short description of the mnemonic to use when
     * @param wordcase Whether to convert strings into uppercase, lowercase,
     * or leave them unchanged.
     * throwing exceptions.
     */
    init {
        strings = ObjectIntMap()
        values = IntMap()
        max = Int.MAX_VALUE
    }

    /**
     * Sets the maximum numeric value
     */
    fun setMaximum(max: Int) {
        this.max = max
    }

    /**
     * Sets the prefix to use when converting to and from values that don't
     * have mnemonics.
     */
    fun setPrefix(prefix: String) {
        this.prefix = sanitize(prefix)
    }

    /* Converts a String to the correct case. */
    private fun sanitize(str: String): String {
        if (wordcase == CASE_UPPER) {
            return str.uppercase(Locale.getDefault())
        } else if (wordcase == CASE_LOWER) {
            return str.lowercase(Locale.getDefault())
        }
        return str
    }

    /**
     * Sets whether numeric values stored in strings are acceptable.
     */
    fun setNumericAllowed(numeric: Boolean) {
        numericok = numeric
    }

    /**
     * Defines the text representation of a numeric value.
     *
     * @param value The numeric value
     * @param string The text string
     */
    fun add(value: Int, string: String) {
        check(value)
        val sanitizedString = sanitize(string)
        strings.put(sanitizedString, value)
        values.put(value, sanitizedString)
    }

    /**
     * Checks that a numeric value is within the range [0..max]
     */
    open fun check(`val`: Int) {
        require(!(`val` < 0 || `val` > max)) { description + " " + `val` + "is out of range" }
    }

    /**
     * Defines an additional text representation of a numeric value.  This will
     * be used by getValue(), but not getText().
     *
     * @param value The numeric value
     * @param string The text string
     */
    fun addAlias(value: Int, string: String) {
        var string = string
        check(value)
        string = sanitize(string)
        strings.put(string, value)
    }

    /**
     * Copies all mnemonics from one table into another.
     *
     * @param source The Mnemonic source to add from
     *
     * @throws IllegalArgumentException The wordcases of the Mnemonics do not
     * match.
     */
    fun addAll(source: Mnemonic) {
        require(wordcase == source.wordcase) { source.description + ": wordcases do not match" }
        strings.putAll(source.strings)
        values.putAll(source.values)
    }

    /**
     * Gets the text mnemonic corresponding to a numeric value.
     *
     * @param value The numeric value
     *
     * @return The corresponding text mnemonic.
     */
    fun getText(value: Int): String {
        check(value)
        var str = values[value]
        if (str != null) {
            return str
        }
        str = Integer.toString(value)
        return if (prefix != null) {
            prefix + str
        } else str
    }

    /**
     * Gets the numeric value corresponding to a text mnemonic.
     *
     * @param string The text mnemonic
     *
     * @return The corresponding numeric value, or -1 if there is none
     */
    fun getValue(string: String): Int {
        val sanitizedString = sanitize(string)
        val value = strings[sanitizedString, INVALID_VALUE]
        if (value != INVALID_VALUE) {
            return value
        }
        if (prefix != null) {
            if (sanitizedString.startsWith(prefix!!)) {
                val `val` = parseNumeric(sanitizedString.substring(prefix!!.length))
                if (`val` >= 0) {
                    return `val`
                }
            }
        }
        return if (numericok) {
            parseNumeric(sanitizedString)
        } else INVALID_VALUE
    }

    private fun parseNumeric(s: String): Int {
        try {
            val `val` = s.toInt()
            if (`val` >= 0 && `val` <= max) {
                return `val`
            }
        } catch (ignored: NumberFormatException) {
        }
        return INVALID_VALUE
    }

    companion object {
        /** Strings are case-sensitive.  */
        const val CASE_SENSITIVE = 1

        /** Strings will be stored/searched for in uppercase.  */
        const val CASE_UPPER = 2

        /** Strings will be stored/searched for in lowercase.  */
        const val CASE_LOWER = 3
        private const val INVALID_VALUE = -1
    }
}
