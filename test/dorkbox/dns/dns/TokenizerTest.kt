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
import dorkbox.dns.dns.exceptions.RelativeNameException
import dorkbox.dns.dns.exceptions.TextParseException
import dorkbox.dns.dns.records.TTL
import dorkbox.dns.dns.utils.Tokenizer
import junit.framework.TestCase
import java.io.BufferedInputStream
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileWriter
import java.io.IOException
import java.util.*

class TokenizerTest : TestCase() {
    private var m_t: Tokenizer? = null
    override fun setUp() {
        m_t = null
    }

    @Throws(IOException::class)
    fun test_get() {
        m_t =
            Tokenizer(BufferedInputStream(ByteArrayInputStream("AnIdentifier \"a quoted \\\" string\"\r\n; this is \"my\"\t(comment)\nanotherIdentifier (\ramultilineIdentifier\n)".toByteArray())))

        var tt = m_t!![true, true]
        assertEquals(Tokenizer.IDENTIFIER, tt.type)
        assertTrue(tt.isString)
        assertFalse(tt.isEOL)
        assertEquals("AnIdentifier", tt.value)

        tt = m_t!![true, true]
        assertEquals(Tokenizer.WHITESPACE, tt.type)
        assertFalse(tt.isString)
        assertFalse(tt.isEOL)
        assertNull(tt.value)

        tt = m_t!![true, true]
        assertEquals(Tokenizer.QUOTED_STRING, tt.type)
        assertTrue(tt.isString)
        assertFalse(tt.isEOL)
        assertEquals("a quoted \\\" string", tt.value)

        tt = m_t!![true, true]
        assertEquals(Tokenizer.EOL, tt.type)
        assertFalse(tt.isString)
        assertTrue(tt.isEOL)
        assertNull(tt.value)

        tt = m_t!![true, true]
        assertEquals(Tokenizer.COMMENT, tt.type)
        assertFalse(tt.isString)
        assertFalse(tt.isEOL)
        assertEquals(" this is \"my\"\t(comment)", tt.value)

        tt = m_t!![true, true]
        assertEquals(Tokenizer.EOL, tt.type)
        assertFalse(tt.isString)
        assertTrue(tt.isEOL)
        assertNull(tt.value)

        tt = m_t!![true, true]
        assertEquals(Tokenizer.IDENTIFIER, tt.type)

        assertTrue(tt.isString)
        assertFalse(tt.isEOL)
        assertEquals("anotherIdentifier", tt.value)

        tt = m_t!![true, true]
        assertEquals(Tokenizer.WHITESPACE, tt.type)

        tt = m_t!![true, true]
        assertEquals(Tokenizer.IDENTIFIER, tt.type)
        assertTrue(tt.isString)
        assertFalse(tt.isEOL)
        assertEquals("amultilineIdentifier", tt.value)

        tt = m_t!![true, true]
        assertEquals(Tokenizer.WHITESPACE, tt.type)

        tt = m_t!![true, true]
        assertEquals(Tokenizer.EOF, tt.type)
        assertFalse(tt.isString)
        assertTrue(tt.isEOL)
        assertNull(tt.value)

        // should be able to do this repeatedly
        tt = m_t!![true, true]
        assertEquals(Tokenizer.EOF, tt.type)
        assertFalse(tt.isString)
        assertTrue(tt.isEOL)
        assertNull(tt.value)

        m_t!!.close()

        m_t = Tokenizer("onlyOneIdentifier")
        tt = m_t!!.get()
        assertEquals(Tokenizer.IDENTIFIER, tt.type)
        assertEquals("onlyOneIdentifier", tt.value)

        m_t!!.close()
        m_t = Tokenizer("identifier ;")
        tt = m_t!!.get()
        assertEquals("identifier", tt.value)

        tt = m_t!!.get()
        assertEquals(Tokenizer.EOF, tt.type)

        m_t!!.close()

        // some ungets
        m_t = Tokenizer("identifier \nidentifier2; junk comment")
        tt = m_t!![true, true]
        assertEquals(Tokenizer.IDENTIFIER, tt.type)
        assertEquals("identifier", tt.value)

        m_t!!.unget()
        tt = m_t!![true, true]
        assertEquals(Tokenizer.IDENTIFIER, tt.type)
        assertEquals("identifier", tt.value)

        tt = m_t!![true, true]
        assertEquals(Tokenizer.WHITESPACE, tt.type)

        m_t!!.unget()
        tt = m_t!![true, true]
        assertEquals(Tokenizer.WHITESPACE, tt.type)

        tt = m_t!![true, true]
        assertEquals(Tokenizer.EOL, tt.type)

        m_t!!.unget()
        tt = m_t!![true, true]
        assertEquals(Tokenizer.EOL, tt.type)

        tt = m_t!![true, true]
        assertEquals(Tokenizer.IDENTIFIER, tt.type)
        assertEquals("identifier2", tt.value)

        tt = m_t!![true, true]
        assertEquals(Tokenizer.COMMENT, tt.type)
        assertEquals(" junk comment", tt.value)

        m_t!!.unget()
        tt = m_t!![true, true]
        assertEquals(Tokenizer.COMMENT, tt.type)
        assertEquals(" junk comment", tt.value)

        tt = m_t!![true, true]
        assertEquals(Tokenizer.EOF, tt.type)

        m_t!!.close()

        m_t = Tokenizer("identifier ( junk ; comment\n )")
        tt = m_t!!.get()
        assertEquals(Tokenizer.IDENTIFIER, tt.type)
        assertEquals(Tokenizer.IDENTIFIER, m_t!!.get().type)
        assertEquals(Tokenizer.EOF, m_t!!.get().type)

        m_t!!.close()
    }

    @Throws(IOException::class)
    fun test_get_invalid() {
        m_t = Tokenizer("(this ;")
        m_t!!.get()
        try {
            m_t!!.get()
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }

        m_t!!.close()
        m_t = Tokenizer("\"bad")
        try {
            m_t!!.get()
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }

        m_t!!.close()
        m_t = Tokenizer(")")
        try {
            m_t!!.get()
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }

        m_t!!.close()
        m_t = Tokenizer("\\")
        try {
            m_t!!.get()
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }

        m_t!!.close()
        m_t = Tokenizer("\"\n")
        try {
            m_t!!.get()
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }
    }

    @Throws(IOException::class)
    fun test_File_input() {
        val tmp = File.createTempFile("dnsjava", "tmp")
        try {
            val fw = FileWriter(tmp)
            fw.write("file\ninput; test")
            fw.close()
            m_t = Tokenizer(tmp)
            var tt = m_t!!.get()
            assertEquals(Tokenizer.IDENTIFIER, tt.type)
            assertEquals("file", tt.value)
            tt = m_t!!.get()
            assertEquals(Tokenizer.EOL, tt.type)
            tt = m_t!!.get()
            assertEquals(Tokenizer.IDENTIFIER, tt.type)
            assertEquals("input", tt.value)
            tt = m_t!![false, true]
            assertEquals(Tokenizer.COMMENT, tt.type)
            assertEquals(" test", tt.value)
            m_t!!.close()
        } finally {
            tmp.delete()
        }
    }

    @Throws(IOException::class)
    fun test_unwanted_comment() {
        m_t = Tokenizer("; this whole thing is a comment\n")
        val tt = m_t!!.get()
        assertEquals(Tokenizer.EOL, tt.type)
    }

    @Throws(IOException::class)
    fun test_unwanted_ungotten_whitespace() {
        m_t = Tokenizer(" ")
        var tt = m_t!![true, true]
        m_t!!.unget()
        tt = m_t!!.get()
        assertEquals(Tokenizer.EOF, tt.type)
    }

    @Throws(IOException::class)
    fun test_unwanted_ungotten_comment() {
        m_t = Tokenizer("; this whole thing is a comment")
        var tt = m_t!![true, true]
        m_t!!.unget()
        tt = m_t!!.get()
        assertEquals(Tokenizer.EOF, tt.type)
    }

    @Throws(IOException::class)
    fun test_empty_string() {
        m_t = Tokenizer("")
        var tt = m_t!!.get()
        assertEquals(Tokenizer.EOF, tt.type)
        m_t = Tokenizer(" ")
        tt = m_t!!.get()
        assertEquals(Tokenizer.EOF, tt.type)
    }

    @Throws(IOException::class)
    fun test_multiple_ungets() {
        m_t = Tokenizer("a simple one")
        val tt = m_t!!.get()
        m_t!!.unget()
        try {
            m_t!!.unget()
            fail("IllegalStateException not thrown")
        } catch (ignored: IllegalStateException) {
        }
    }

    @Throws(IOException::class)
    fun test_getString() {
        m_t = Tokenizer("just_an_identifier")
        var out = m_t!!.getString()
        assertEquals("just_an_identifier", out)

        m_t = Tokenizer("\"just a string\"")
        out = m_t!!.getString()
        assertEquals("just a string", out)

        m_t = Tokenizer("; just a comment")
        try {
            out = m_t!!.getString()
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }
    }

    @Throws(IOException::class)
    fun test_getIdentifier() {
        m_t = Tokenizer("just_an_identifier")
        val out = m_t!!.getIdentifier()
        assertEquals("just_an_identifier", out)

        m_t = Tokenizer("\"just a string\"")
        try {
            m_t!!.getIdentifier()
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }
    }

    @Throws(IOException::class)
    fun test_getLong() {
        m_t = Tokenizer((Int.MAX_VALUE + 1L).toString() + "")
        val out = m_t!!.getLong()
        assertEquals(Int.MAX_VALUE + 1L, out)

        m_t = Tokenizer("-10")
        try {
            m_t!!.getLong()
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }

        m_t = Tokenizer("19_identifier")
        try {
            m_t!!.getLong()
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }
    }

    @Throws(IOException::class)
    fun test_getUInt32() {
        m_t = Tokenizer(0xABCDEF12L.toString() + "")
        val out = m_t!!.getUInt32()
        assertEquals(0xABCDEF12L, out)

        m_t = Tokenizer(0x100000000L.toString() + "")
        try {
            m_t!!.getUInt32()
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }

        m_t = Tokenizer("-12345")
        try {
            m_t!!.getUInt32()
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }
    }

    @Throws(IOException::class)
    fun test_getUInt16() {
        m_t = Tokenizer(0xABCDL.toString() + "")
        val out = m_t!!.getUInt16()
        assertEquals(0xABCDL, out.toLong())

        m_t = Tokenizer(0x10000.toString() + "")
        try {
            m_t!!.getUInt16()
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }

        m_t = Tokenizer("-125")
        try {
            m_t!!.getUInt16()
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }
    }

    @Throws(IOException::class)
    fun test_getUInt8() {
        m_t = Tokenizer(0xCDL.toString() + "")
        val out = m_t!!.getUInt8()
        assertEquals(0xCDL, out.toLong())

        m_t = Tokenizer(0x100.toString() + "")
        try {
            m_t!!.getUInt8()
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }

        m_t = Tokenizer("-12")
        try {
            m_t!!.getUInt8()
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }
    }

    @Throws(IOException::class)
    fun test_getTTL() {
        m_t = Tokenizer("59S")
        assertEquals(59, m_t!!.getTTL())

        m_t = Tokenizer(TTL.MAX_VALUE.toString() + "")
        assertEquals(TTL.MAX_VALUE, m_t!!.getTTL())

        m_t = Tokenizer((TTL.MAX_VALUE + 1L).toString() + "")
        assertEquals(TTL.MAX_VALUE, m_t!!.getTTL())

        m_t = Tokenizer("Junk")
        try {
            m_t!!.getTTL()
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }
    }

    @Throws(IOException::class)
    fun test_getTTLLike() {
        m_t = Tokenizer("59S")
        assertEquals(59, m_t!!.getTTLLike())

        m_t = Tokenizer(TTL.MAX_VALUE.toString() + "")
        assertEquals(TTL.MAX_VALUE, m_t!!.getTTLLike())

        m_t = Tokenizer((TTL.MAX_VALUE + 1L).toString() + "")
        assertEquals(TTL.MAX_VALUE + 1L, m_t!!.getTTLLike())

        m_t = Tokenizer("Junk")
        try {
            m_t!!.getTTLLike()
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }
    }

    @Throws(IOException::class, TextParseException::class)
    fun test_getName() {
        val root = fromString(".")
        m_t = Tokenizer("junk")
        val exp = fromString("junk.")
        val out = m_t!!.getName(root)
        assertEquals(exp, out)

        val rel = fromString("you.dig")
        m_t = Tokenizer("junk")
        try {
            m_t!!.getName(rel)
            fail("RelativeNameException not thrown")
        } catch (ignored: RelativeNameException) {
        }

        m_t = Tokenizer("")
        try {
            m_t!!.getName(root)
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }
    }

    @Throws(IOException::class)
    fun test_getEOL() {
        m_t = Tokenizer("id")
        m_t!!.getIdentifier()
        try {
            m_t!!.getEOL()
        } catch (e: TextParseException) {
            fail(e.message)
        }

        m_t = Tokenizer("\n")
        try {
            m_t!!.getEOL()
            m_t!!.getEOL()
        } catch (e: TextParseException) {
            fail(e.message)
        }

        m_t = Tokenizer("id")
        try {
            m_t!!.getEOL()
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }
    }

    @Throws(IOException::class)
    fun test_getBase64() {
        val exp = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9)
        // basic
        m_t = Tokenizer("AQIDBAUGBwgJ")
        var out = m_t!!.base64
        assertEquals(exp, out)

        // with some whitespace
        m_t = Tokenizer("AQIDB AUGB   wgJ")
        out = m_t!!.base64
        assertEquals(exp, out)

        // two base64s separated by newline
        m_t = Tokenizer("AQIDBAUGBwgJ\nAB23DK")
        out = m_t!!.base64
        assertEquals(exp, out)

        // no remaining strings
        m_t = Tokenizer("\n")
        assertNull(m_t!!.base64)
        m_t = Tokenizer("\n")
        try {
            m_t!!.getBase64(true)
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }

        // invalid encoding
        m_t = Tokenizer("not_base64")
        try {
            m_t!!.getBase64(false)
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }
        m_t = Tokenizer("not_base64")
        try {
            m_t!!.getBase64(true)
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }
    }

    private fun assertEquals(exp: ByteArray, act: ByteArray?) {
        assertTrue(Arrays.equals(exp, act))
    }

    @Throws(IOException::class)
    fun test_getHex() {
        val exp = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
        // basic
        m_t = Tokenizer("0102030405060708090A0B0C0D0E0F")
        var out = m_t!!.hex
        assertEquals(exp, out)

        // with some whitespace
        m_t = Tokenizer("0102030 405 060708090A0B0C      0D0E0F")
        out = m_t!!.hex
        assertEquals(exp, out)

        // two hexs separated by newline
        m_t = Tokenizer("0102030405060708090A0B0C0D0E0F\n01AB3FE")
        out = m_t!!.hex
        assertEquals(exp, out)

        // no remaining strings
        m_t = Tokenizer("\n")
        assertNull(m_t!!.hex)
        m_t = Tokenizer("\n")
        try {
            m_t!!.getHex(true)
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }

        // invalid encoding
        m_t = Tokenizer("not_hex")
        try {
            m_t!!.getHex(false)
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }
        m_t = Tokenizer("not_hex")
        try {
            m_t!!.getHex(true)
            fail("TextParseException not thrown")
        } catch (ignored: TextParseException) {
        }
    }
}
