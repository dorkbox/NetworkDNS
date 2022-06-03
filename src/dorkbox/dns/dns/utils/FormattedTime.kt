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
package dorkbox.dns.dns.utils

import dorkbox.dns.dns.exceptions.TextParseException
import java.text.DecimalFormat
import java.util.*

/**
 * Routines for converting time values to and from YYYYMMDDHHMMSS format.
 *
 * @author Brian Wellington
 */
object FormattedTime {
    private val w2 = DecimalFormat()
    private val w4 = DecimalFormat()

    init {
        w2.minimumIntegerDigits = 2
        w4.minimumIntegerDigits = 4
        w4.isGroupingUsed = false
    }

    /**
     * Converts a Date into a formatted string.
     *
     * @param date The Date to convert.
     *
     * @return The formatted string.
     */
    fun format(date: Date?): String {
        val c: Calendar = GregorianCalendar(TimeZone.getTimeZone("UTC"))

        val sb = StringBuilder()
        c.time = date

        sb.append(w4.format(c[Calendar.YEAR].toLong()))
        sb.append(w2.format((c[Calendar.MONTH] + 1).toLong()))
        sb.append(w2.format(c[Calendar.DAY_OF_MONTH].toLong()))
        sb.append(w2.format(c[Calendar.HOUR_OF_DAY].toLong()))
        sb.append(w2.format(c[Calendar.MINUTE].toLong()))
        sb.append(w2.format(c[Calendar.SECOND].toLong()))
        return sb.toString()
    }

    /**
     * Parses a formatted time string into a Date.
     *
     * @param s The string, in the form YYYYMMDDHHMMSS.
     *
     * @return The Date object.
     *
     * @throws TextParseException The string was invalid.
     */
    @Throws(TextParseException::class)
    fun parse(s: String): Date {
        if (s.length != 14) {
            throw TextParseException("Invalid time encoding: $s")
        }
        val c: Calendar = GregorianCalendar(TimeZone.getTimeZone("UTC"))
        c.clear()

        try {
            val year = s.substring(0, 4).toInt()
            val month = s.substring(4, 6).toInt() - 1
            val date = s.substring(6, 8).toInt()
            val hour = s.substring(8, 10).toInt()
            val minute = s.substring(10, 12).toInt()
            val second = s.substring(12, 14).toInt()
            c[year, month, date, hour, minute] = second
        } catch (e: NumberFormatException) {
            throw TextParseException("Invalid time encoding: $s")
        }
        return c.time
    }
}
