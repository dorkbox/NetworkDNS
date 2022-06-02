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

import dorkbox.dns.dns.exceptions.InvalidTTLException

/**
 * Routines for parsing BIND-style TTL values.  These values consist of
 * numbers followed by 1 letter units of time (W - week, D - day, H - hour,
 * M - minute, S - second).
 *
 * @author Brian Wellington
 */
object TTL {
    const val MAX_VALUE = 0x7FFFFFFFL

    /**
     * Parses a TTL, which can either be expressed as a number or a BIND-style
     * string with numbers and units.
     *
     * @param s The string representing the TTL
     *
     * @return The TTL as a number of seconds
     *
     * @throws NumberFormatException The string was not in a valid TTL format.
     */
    fun parseTTL(s: String): Long {
        return parse(s, true)
    }

    /**
     * Parses a TTL-like value, which can either be expressed as a number or a
     * BIND-style string with numbers and units.
     *
     * @param s The string representing the numeric value.
     * @param clamp Whether to clamp values in the range [MAX_VALUE + 1, 2^32 -1]
     * to MAX_VALUE.  This should be donw for TTLs, but not other values which
     * can be expressed in this format.
     *
     * @return The value as a number of seconds
     *
     * @throws NumberFormatException The string was not in a valid TTL format.
     */
    fun parse(s: String, clamp: Boolean): Long {
        if (s.length == 0 || !Character.isDigit(s[0])) {
            throw NumberFormatException()
        }
        var value: Long = 0
        var ttl: Long = 0
        for (i in 0 until s.length) {
            val c = s[i]
            val oldvalue = value
            if (Character.isDigit(c)) {
                value = value * 10 + Character.getNumericValue(c)
                if (value < oldvalue) {
                    throw NumberFormatException()
                }
            } else {
                when (c.uppercaseChar()) {
                    'W' -> {
                        value *= 7
                        value *= 24
                        value *= 60
                        value *= 60
                    }
                    'D' -> {
                        value *= 24
                        value *= 60
                        value *= 60
                    }
                    'H' -> {
                        value *= 60
                        value *= 60
                    }
                    'M' -> value *= 60
                    'S' -> {}
                    else -> throw NumberFormatException()
                }
                ttl += value
                value = 0
                if (ttl > 0xFFFFFFFFL) {
                    throw NumberFormatException()
                }
            }
        }
        if (ttl == 0L) {
            ttl = value
        }
        if (ttl > 0xFFFFFFFFL) {
            throw NumberFormatException()
        } else if (ttl > MAX_VALUE && clamp) {
            ttl = MAX_VALUE
        }
        return ttl
    }

    fun format(ttl: Long): String {
        var ttl = ttl
        check(ttl)
        val sb = StringBuilder()
        val secs: Long
        val mins: Long
        val hours: Long
        val days: Long
        val weeks: Long
        secs = ttl % 60
        ttl /= 60
        mins = ttl % 60
        ttl /= 60
        hours = ttl % 24
        ttl /= 24
        days = ttl % 7
        ttl /= 7
        weeks = ttl
        if (weeks > 0) {
            sb.append(weeks).append("W")
        }
        if (days > 0) {
            sb.append(days).append("D")
        }
        if (hours > 0) {
            sb.append(hours).append("H")
        }
        if (mins > 0) {
            sb.append(mins).append("M")
        }
        if (secs > 0 || weeks == 0L && days == 0L && hours == 0L && mins == 0L) {
            sb.append(secs).append("S")
        }
        return sb.toString()
    }

    fun check(i: Long) {
        if (i < 0 || i > MAX_VALUE) {
            throw InvalidTTLException(i)
        }
    }
}
