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

import dorkbox.dns.dns.Name.Companion.fromString
import dorkbox.dns.dns.exceptions.InvalidDClassException
import dorkbox.dns.dns.exceptions.InvalidTTLException
import dorkbox.dns.dns.exceptions.InvalidTypeException
import dorkbox.dns.dns.exceptions.NameTooLongException
import dorkbox.dns.dns.exceptions.RelativeNameException
import dorkbox.dns.dns.exceptions.TextParseException
import dorkbox.dns.dns.exceptions.WireParseException
import dorkbox.dns.dns.exceptions.ZoneTransferException
import junit.framework.TestCase
import java.io.IOException

class ExceptionTest : TestCase() {
    fun test_InvalidDClassException() {
        val e: IllegalArgumentException = InvalidDClassException(10)
        assertEquals("Invalid DNS class: 10", e.message)
    }

    fun test_InvalidTTLException() {
        val e: IllegalArgumentException = InvalidTTLException(32345)
        assertEquals("Invalid DNS TTL: 32345", e.message)
    }

    fun test_InvalidTypeException() {
        val e: IllegalArgumentException = InvalidTypeException(32345)
        assertEquals("Invalid DNS type: 32345", e.message)
    }

    fun test_NameTooLongException() {
        var e: WireParseException = NameTooLongException()
        assertNull(e.message)

        e = NameTooLongException("This is my too long name")
        assertEquals("This is my too long name", e.message)
    }

    @Throws(TextParseException::class)
    fun test_RelativeNameException() {
        var e: IllegalArgumentException = RelativeNameException("This is my relative name")
        assertEquals("This is my relative name", e.message)

        e = RelativeNameException(fromString("relative"))
        assertEquals("'relative' is not an absolute name", e.message)
    }

    fun test_TextParseException() {
        var e: IOException = TextParseException()
        assertNull(e.message)

        e = TextParseException("This is my message")
        assertEquals("This is my message", e.message)
    }

    fun test_WireParseException() {
        var e: IOException = WireParseException()
        assertNull(e.message)

        e = WireParseException("This is my message")
        assertEquals("This is my message", e.message)
    }

    fun test_ZoneTransferException() {
        var e: Exception = ZoneTransferException()
        assertNull(e.message)

        e = ZoneTransferException("This is my message")
        assertEquals("This is my message", e.message)
    }
}
