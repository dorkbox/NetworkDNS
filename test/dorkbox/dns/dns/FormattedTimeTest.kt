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

import dorkbox.dns.dns.exceptions.TextParseException
import dorkbox.dns.dns.utils.FormattedTime.format
import dorkbox.dns.dns.utils.FormattedTime.parse
import junit.framework.TestCase
import java.util.*

class FormattedTimeTest : TestCase() {
    fun test_format() {
        val cal = GregorianCalendar(TimeZone.getTimeZone("UTC"))
        cal[2005, 2, 19, 4, 4] = 5
        val out = format(cal.time)
        assertEquals("20050319040405", out)
    }

    @Throws(TextParseException::class)
    fun test_parse() {
        // have to make sure to clear out the milliseconds since there
        // is occasionally a difference between when cal and cal2 are
        // instantiated.
        val cal = GregorianCalendar(TimeZone.getTimeZone("UTC"))
        cal[2005, 2, 19, 4, 4] = 5
        cal[Calendar.MILLISECOND] = 0
        val out = parse("20050319040405")
        val cal2 = GregorianCalendar(TimeZone.getTimeZone("UTC"))
        cal2.timeInMillis = out.time
        cal2[Calendar.MILLISECOND] = 0
        assertEquals(cal, cal2)
    }

    fun test_parse_invalid() {
        try {
            parse("2004010101010")
            fail("TextParseException not thrown")
         } catch (ignored: TextParseException) {
        }
        try {
            parse("200401010101010")
            fail("TextParseException not thrown")
         } catch (ignored: TextParseException) {
        }
        try {
            parse("2004010101010A")
            fail("TextParseException not thrown")
         } catch (ignored: TextParseException) {
        }
    }
}
