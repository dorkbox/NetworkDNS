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

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.exceptions.RelativeNameException;
import dorkbox.dns.dns.exceptions.TextParseException;
import dorkbox.dns.dns.records.TTL;
import dorkbox.dns.dns.utils.Tokenizer;
import junit.framework.TestCase;

public
class TokenizerTest extends TestCase {
    private Tokenizer m_t;

    @Override
    protected
    void setUp() {
        m_t = null;
    }

    public
    void test_get() throws IOException {
        m_t = new Tokenizer(new BufferedInputStream(new ByteArrayInputStream("AnIdentifier \"a quoted \\\" string\"\r\n; this is \"my\"\t(comment)\nanotherIdentifier (\ramultilineIdentifier\n)".getBytes())));

        Tokenizer.Token tt = m_t.get(true, true);
        assertEquals(Tokenizer.IDENTIFIER, tt.type);
        assertTrue(tt.isString());
        assertFalse(tt.isEOL());
        assertEquals("AnIdentifier", tt.value);

        tt = m_t.get(true, true);
        assertEquals(Tokenizer.WHITESPACE, tt.type);
        assertFalse(tt.isString());
        assertFalse(tt.isEOL());
        assertNull(tt.value);

        tt = m_t.get(true, true);
        assertEquals(Tokenizer.QUOTED_STRING, tt.type);
        assertTrue(tt.isString());
        assertFalse(tt.isEOL());
        assertEquals("a quoted \\\" string", tt.value);

        tt = m_t.get(true, true);
        assertEquals(Tokenizer.EOL, tt.type);
        assertFalse(tt.isString());
        assertTrue(tt.isEOL());
        assertNull(tt.value);

        tt = m_t.get(true, true);
        assertEquals(Tokenizer.COMMENT, tt.type);
        assertFalse(tt.isString());
        assertFalse(tt.isEOL());
        assertEquals(" this is \"my\"\t(comment)", tt.value);

        tt = m_t.get(true, true);
        assertEquals(Tokenizer.EOL, tt.type);
        assertFalse(tt.isString());
        assertTrue(tt.isEOL());
        assertNull(tt.value);

        tt = m_t.get(true, true);
        assertEquals(Tokenizer.IDENTIFIER, tt.type);
        assertTrue(tt.isString());
        assertFalse(tt.isEOL());
        assertEquals("anotherIdentifier", tt.value);

        tt = m_t.get(true, true);
        assertEquals(Tokenizer.WHITESPACE, tt.type);

        tt = m_t.get(true, true);
        assertEquals(Tokenizer.IDENTIFIER, tt.type);
        assertTrue(tt.isString());
        assertFalse(tt.isEOL());
        assertEquals("amultilineIdentifier", tt.value);

        tt = m_t.get(true, true);
        assertEquals(Tokenizer.WHITESPACE, tt.type);

        tt = m_t.get(true, true);
        assertEquals(Tokenizer.EOF, tt.type);
        assertFalse(tt.isString());
        assertTrue(tt.isEOL());
        assertNull(tt.value);

        // should be able to do this repeatedly
        tt = m_t.get(true, true);
        assertEquals(Tokenizer.EOF, tt.type);
        assertFalse(tt.isString());
        assertTrue(tt.isEOL());
        assertNull(tt.value);

        m_t.close();

        m_t = new Tokenizer("onlyOneIdentifier");
        tt = m_t.get();
        assertEquals(Tokenizer.IDENTIFIER, tt.type);
        assertEquals("onlyOneIdentifier", tt.value);

        m_t.close();

        m_t = new Tokenizer("identifier ;");
        tt = m_t.get();
        assertEquals("identifier", tt.value);
        tt = m_t.get();
        assertEquals(Tokenizer.EOF, tt.type);

        m_t.close();

        // some ungets
        m_t = new Tokenizer("identifier \nidentifier2; junk comment");
        tt = m_t.get(true, true);
        assertEquals(Tokenizer.IDENTIFIER, tt.type);
        assertEquals("identifier", tt.value);

        m_t.unget();

        tt = m_t.get(true, true);
        assertEquals(Tokenizer.IDENTIFIER, tt.type);
        assertEquals("identifier", tt.value);

        tt = m_t.get(true, true);
        assertEquals(Tokenizer.WHITESPACE, tt.type);

        m_t.unget();
        tt = m_t.get(true, true);
        assertEquals(Tokenizer.WHITESPACE, tt.type);

        tt = m_t.get(true, true);
        assertEquals(Tokenizer.EOL, tt.type);

        m_t.unget();
        tt = m_t.get(true, true);
        assertEquals(Tokenizer.EOL, tt.type);

        tt = m_t.get(true, true);
        assertEquals(Tokenizer.IDENTIFIER, tt.type);
        assertEquals("identifier2", tt.value);

        tt = m_t.get(true, true);
        assertEquals(Tokenizer.COMMENT, tt.type);
        assertEquals(" junk comment", tt.value);

        m_t.unget();
        tt = m_t.get(true, true);
        assertEquals(Tokenizer.COMMENT, tt.type);
        assertEquals(" junk comment", tt.value);

        tt = m_t.get(true, true);
        assertEquals(Tokenizer.EOF, tt.type);

        m_t.close();

        m_t = new Tokenizer("identifier ( junk ; comment\n )");
        tt = m_t.get();
        assertEquals(Tokenizer.IDENTIFIER, tt.type);
        assertEquals(Tokenizer.IDENTIFIER, m_t.get().type);
        assertEquals(Tokenizer.EOF, m_t.get().type);

        m_t.close();
    }

    public
    void test_get_invalid() throws IOException {
        m_t = new Tokenizer("(this ;");
        m_t.get();
        try {
            m_t.get();
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }

        m_t.close();

        m_t = new Tokenizer("\"bad");
        try {
            m_t.get();
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }

        m_t.close();

        m_t = new Tokenizer(")");
        try {
            m_t.get();
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }

        m_t.close();

        m_t = new Tokenizer("\\");
        try {
            m_t.get();
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }

        m_t.close();

        m_t = new Tokenizer("\"\n");
        try {
            m_t.get();
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }
    }

    public
    void test_File_input() throws IOException {
        File tmp = File.createTempFile("dnsjava", "tmp");
        try {
            FileWriter fw = new FileWriter(tmp);
            fw.write("file\ninput; test");
            fw.close();

            m_t = new Tokenizer(tmp);

            Tokenizer.Token tt = m_t.get();
            assertEquals(Tokenizer.IDENTIFIER, tt.type);
            assertEquals("file", tt.value);

            tt = m_t.get();
            assertEquals(Tokenizer.EOL, tt.type);

            tt = m_t.get();
            assertEquals(Tokenizer.IDENTIFIER, tt.type);
            assertEquals("input", tt.value);

            tt = m_t.get(false, true);
            assertEquals(Tokenizer.COMMENT, tt.type);
            assertEquals(" test", tt.value);

            m_t.close();
        } finally {
            tmp.delete();
        }
    }

    public
    void test_unwanted_comment() throws IOException {
        m_t = new Tokenizer("; this whole thing is a comment\n");
        Tokenizer.Token tt = m_t.get();

        assertEquals(Tokenizer.EOL, tt.type);
    }

    public
    void test_unwanted_ungotten_whitespace() throws IOException {
        m_t = new Tokenizer(" ");
        Tokenizer.Token tt = m_t.get(true, true);
        m_t.unget();
        tt = m_t.get();
        assertEquals(Tokenizer.EOF, tt.type);
    }

    public
    void test_unwanted_ungotten_comment() throws IOException {
        m_t = new Tokenizer("; this whole thing is a comment");
        Tokenizer.Token tt = m_t.get(true, true);
        m_t.unget();
        tt = m_t.get();
        assertEquals(Tokenizer.EOF, tt.type);
    }

    public
    void test_empty_string() throws IOException {
        m_t = new Tokenizer("");
        Tokenizer.Token tt = m_t.get();
        assertEquals(Tokenizer.EOF, tt.type);

        m_t = new Tokenizer(" ");
        tt = m_t.get();
        assertEquals(Tokenizer.EOF, tt.type);
    }

    public
    void test_multiple_ungets() throws IOException {
        m_t = new Tokenizer("a simple one");
        Tokenizer.Token tt = m_t.get();

        m_t.unget();
        try {
            m_t.unget();
            fail("IllegalStateException not thrown");
        } catch (IllegalStateException e) {
        }
    }

    public
    void test_getString() throws IOException {
        m_t = new Tokenizer("just_an_identifier");
        String out = m_t.getString();
        assertEquals("just_an_identifier", out);

        m_t = new Tokenizer("\"just a string\"");
        out = m_t.getString();
        assertEquals("just a string", out);

        m_t = new Tokenizer("; just a comment");
        try {
            out = m_t.getString();
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }
    }

    public
    void test_getIdentifier() throws IOException {
        m_t = new Tokenizer("just_an_identifier");
        String out = m_t.getIdentifier();
        assertEquals("just_an_identifier", out);

        m_t = new Tokenizer("\"just a string\"");
        try {
            m_t.getIdentifier();
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }
    }

    public
    void test_getLong() throws IOException {
        m_t = new Tokenizer((Integer.MAX_VALUE + 1L) + "");
        long out = m_t.getLong();
        assertEquals((Integer.MAX_VALUE + 1L), out);

        m_t = new Tokenizer("-10");
        try {
            m_t.getLong();
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }

        m_t = new Tokenizer("19_identifier");
        try {
            m_t.getLong();
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }
    }

    public
    void test_getUInt32() throws IOException {
        m_t = new Tokenizer(0xABCDEF12L + "");
        long out = m_t.getUInt32();
        assertEquals(0xABCDEF12L, out);

        m_t = new Tokenizer(0x100000000L + "");
        try {
            m_t.getUInt32();
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }

        m_t = new Tokenizer("-12345");
        try {
            m_t.getUInt32();
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }
    }

    public
    void test_getUInt16() throws IOException {
        m_t = new Tokenizer(0xABCDL + "");
        int out = m_t.getUInt16();
        assertEquals(0xABCDL, out);

        m_t = new Tokenizer(0x10000 + "");
        try {
            m_t.getUInt16();
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }

        m_t = new Tokenizer("-125");
        try {
            m_t.getUInt16();
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }
    }

    public
    void test_getUInt8() throws IOException {
        m_t = new Tokenizer(0xCDL + "");
        int out = m_t.getUInt8();
        assertEquals(0xCDL, out);

        m_t = new Tokenizer(0x100 + "");
        try {
            m_t.getUInt8();
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }

        m_t = new Tokenizer("-12");
        try {
            m_t.getUInt8();
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }
    }

    public
    void test_getTTL() throws IOException {
        m_t = new Tokenizer("59S");
        assertEquals(59, m_t.getTTL());

        m_t = new Tokenizer(TTL.MAX_VALUE + "");
        assertEquals(TTL.MAX_VALUE, m_t.getTTL());

        m_t = new Tokenizer((TTL.MAX_VALUE + 1L) + "");
        assertEquals(TTL.MAX_VALUE, m_t.getTTL());

        m_t = new Tokenizer("Junk");
        try {
            m_t.getTTL();
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }
    }

    public
    void test_getTTLLike() throws IOException {
        m_t = new Tokenizer("59S");
        assertEquals(59, m_t.getTTLLike());

        m_t = new Tokenizer(TTL.MAX_VALUE + "");
        assertEquals(TTL.MAX_VALUE, m_t.getTTLLike());

        m_t = new Tokenizer((TTL.MAX_VALUE + 1L) + "");
        assertEquals(TTL.MAX_VALUE + 1L, m_t.getTTLLike());

        m_t = new Tokenizer("Junk");
        try {
            m_t.getTTLLike();
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }
    }

    public
    void test_getName() throws IOException, TextParseException {
        Name root = Name.fromString(".");
        m_t = new Tokenizer("junk");
        Name exp = Name.fromString("junk.");
        Name out = m_t.getName(root);
        assertEquals(exp, out);

        Name rel = Name.fromString("you.dig");
        m_t = new Tokenizer("junk");
        try {
            m_t.getName(rel);
            fail("RelativeNameException not thrown");
        } catch (RelativeNameException e) {
        }

        m_t = new Tokenizer("");
        try {
            m_t.getName(root);
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }
    }

    public
    void test_getEOL() throws IOException {
        m_t = new Tokenizer("id");
        m_t.getIdentifier();
        try {
            m_t.getEOL();
        } catch (TextParseException e) {
            fail(e.getMessage());
        }

        m_t = new Tokenizer("\n");
        try {
            m_t.getEOL();
            m_t.getEOL();
        } catch (TextParseException e) {
            fail(e.getMessage());
        }

        m_t = new Tokenizer("id");
        try {
            m_t.getEOL();
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }
    }

    public
    void test_getBase64() throws IOException {
        byte[] exp = {1, 2, 3, 4, 5, 6, 7, 8, 9};
        // basic
        m_t = new Tokenizer("AQIDBAUGBwgJ");
        byte[] out = m_t.getBase64();
        assertEquals(exp, out);

        // with some whitespace
        m_t = new Tokenizer("AQIDB AUGB   wgJ");
        out = m_t.getBase64();
        assertEquals(exp, out);

        // two base64s separated by newline
        m_t = new Tokenizer("AQIDBAUGBwgJ\nAB23DK");
        out = m_t.getBase64();
        assertEquals(exp, out);

        // no remaining strings
        m_t = new Tokenizer("\n");
        assertNull(m_t.getBase64());

        m_t = new Tokenizer("\n");
        try {
            m_t.getBase64(true);
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }

        // invalid encoding
        m_t = new Tokenizer("not_base64");
        try {
            m_t.getBase64(false);
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }

        m_t = new Tokenizer("not_base64");
        try {
            m_t.getBase64(true);
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }
    }

    private
    void assertEquals(byte[] exp, byte[] act) {
        assertTrue(java.util.Arrays.equals(exp, act));
    }

    public
    void test_getHex() throws IOException {
        byte[] exp = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        // basic
        m_t = new Tokenizer("0102030405060708090A0B0C0D0E0F");
        byte[] out = m_t.getHex();
        assertEquals(exp, out);

        // with some whitespace
        m_t = new Tokenizer("0102030 405 060708090A0B0C      0D0E0F");
        out = m_t.getHex();
        assertEquals(exp, out);

        // two hexs separated by newline
        m_t = new Tokenizer("0102030405060708090A0B0C0D0E0F\n01AB3FE");
        out = m_t.getHex();
        assertEquals(exp, out);

        // no remaining strings
        m_t = new Tokenizer("\n");
        assertNull(m_t.getHex());

        m_t = new Tokenizer("\n");
        try {
            m_t.getHex(true);
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }

        // invalid encoding
        m_t = new Tokenizer("not_hex");
        try {
            m_t.getHex(false);
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }

        m_t = new Tokenizer("not_hex");
        try {
            m_t.getHex(true);
            fail("TextParseException not thrown");
        } catch (TextParseException e) {
        }
    }
}
