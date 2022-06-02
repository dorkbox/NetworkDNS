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

import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;

import dorkbox.dns.dns.exceptions.TextParseException;
import dorkbox.dns.dns.utils.FormattedTime;
import junit.framework.TestCase;

public
class FormattedTimeTest extends TestCase {
    public
    void test_format() {
        GregorianCalendar cal = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        cal.set(2005, 2, 19, 4, 4, 5);
        String out = FormattedTime.INSTANCE.format(cal.getTime());
        assertEquals("20050319040405", out);
    }

    public
    void test_parse() throws TextParseException {
        // have to make sure to clear out the milliseconds since there
        // is occasionally a difference between when cal and cal2 are
        // instantiated.
        GregorianCalendar cal = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        cal.set(2005, 2, 19, 4, 4, 5);
        cal.set(Calendar.MILLISECOND, 0);

        Date out = FormattedTime.parse("20050319040405");
        GregorianCalendar cal2 = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
        cal2.setTimeInMillis(out.getTime());
        cal2.set(Calendar.MILLISECOND, 0);
        assertEquals(cal, cal2);
    }

    public
    void test_parse_invalid() {
        try {
            FormattedTime.parse("2004010101010");
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }
        try {
            FormattedTime.parse("200401010101010");
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }
        try {
            FormattedTime.parse("2004010101010A");
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }
    }
}
