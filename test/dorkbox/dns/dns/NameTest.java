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

import java.io.IOException;
import java.util.Arrays;

import dorkbox.dns.dns.constants.DnsClass;
import dorkbox.dns.dns.exceptions.NameTooLongException;
import dorkbox.dns.dns.exceptions.TextParseException;
import dorkbox.dns.dns.exceptions.WireParseException;
import dorkbox.dns.dns.records.DNAMERecord;
import dorkbox.dns.dns.utils.Options;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public
class NameTest extends TestCase {
    public static
    class Test_String_init extends TestCase {
        private final String m_abs = "WWW.DnsJava.org.";
        private Name m_abs_origin;
        private final String m_rel = "WWW.DnsJava";
        private Name m_rel_origin;

        @Override
        protected
        void setUp() throws TextParseException {
            m_abs_origin = Name.Companion.fromString("Orig.", null);
            m_rel_origin = Name.Companion.fromString("Orig", null);
        }

        public
        void test_ctor_empty() {
            try {
                new Name("", null);
                fail("TextParseException not thrown");
            } catch (TextParseException e) {
            }
        }

        public
        void test_ctor_at_null_origin() throws TextParseException {
            Name n = new Name("@", null);
            assertFalse(n.isAbsolute());
            assertFalse(n.isWild());
            assertEquals(0, n.labels());
            assertEquals(0, n.length());
        }

        public
        void test_ctor_at_abs_origin() throws TextParseException {
            Name n = new Name("@", m_abs_origin);
            assertEquals(m_abs_origin, n);
        }

        public
        void test_ctor_at_rel_origin() throws TextParseException {
            Name n = new Name("@", m_rel_origin);
            assertEquals(m_rel_origin, n);
        }

        public
        void test_ctor_dot() throws TextParseException {
            Name n = new Name(".", null);
            assertEquals(Name.getRoot(), n);
            assertNotSame(Name.getRoot(), n);
            assertEquals(1, n.labels());
            assertEquals(1, n.length());
        }

        public
        void test_ctor_wildcard() throws TextParseException {
            Name n = new Name("*", null);
            assertFalse(n.isAbsolute());
            assertTrue(n.isWild());
            assertEquals(1, n.labels());
            assertEquals(2, n.length());
            assertTrue(Arrays.equals(new byte[] {1, '*'}, n.getLabel(0)));
            assertEquals("*", n.getLabelString(0));
        }

        public
        void test_ctor_abs() throws TextParseException {
            Name n = new Name(m_abs, null);
            assertTrue(n.isAbsolute());
            assertFalse(n.isWild());
            assertEquals(4, n.labels());
            assertEquals(17, n.length());
            assertTrue(Arrays.equals(new byte[] {3, 'W', 'W', 'W'}, n.getLabel(0)));
            assertEquals("WWW", n.getLabelString(0));
            assertTrue(Arrays.equals(new byte[] {7, 'D', 'n', 's', 'J', 'a', 'v', 'a'}, n.getLabel(1)));
            assertEquals("DnsJava", n.getLabelString(1));
            assertTrue(Arrays.equals(new byte[] {3, 'o', 'r', 'g'}, n.getLabel(2)));
            assertEquals("org", n.getLabelString(2));
            assertTrue(Arrays.equals(new byte[] {0}, n.getLabel(3)));
            assertEquals("", n.getLabelString(3));
        }

        public
        void test_ctor_rel() throws TextParseException {
            Name n = new Name(m_rel, null);
            assertFalse(n.isAbsolute());
            assertFalse(n.isWild());
            assertEquals(2, n.labels());
            assertEquals(12, n.length());
            assertTrue(Arrays.equals(new byte[] {3, 'W', 'W', 'W'}, n.getLabel(0)));
            assertEquals("WWW", n.getLabelString(0));
            assertTrue(Arrays.equals(new byte[] {7, 'D', 'n', 's', 'J', 'a', 'v', 'a'}, n.getLabel(1)));
            assertEquals("DnsJava", n.getLabelString(1));
        }

        public
        void test_ctor_7label() throws TextParseException {
            // 7 is the number of label positions that are cached
            Name n = new Name("a.b.c.d.e.f.", null);
            assertTrue(n.isAbsolute());
            assertFalse(n.isWild());
            assertEquals(7, n.labels());
            assertEquals(13, n.length());
            assertTrue(Arrays.equals(new byte[] {1, 'a'}, n.getLabel(0)));
            assertEquals("a", n.getLabelString(0));
            assertTrue(Arrays.equals(new byte[] {1, 'b'}, n.getLabel(1)));
            assertEquals("b", n.getLabelString(1));
            assertTrue(Arrays.equals(new byte[] {1, 'c'}, n.getLabel(2)));
            assertEquals("c", n.getLabelString(2));
            assertTrue(Arrays.equals(new byte[] {1, 'd'}, n.getLabel(3)));
            assertEquals("d", n.getLabelString(3));
            assertTrue(Arrays.equals(new byte[] {1, 'e'}, n.getLabel(4)));
            assertEquals("e", n.getLabelString(4));
            assertTrue(Arrays.equals(new byte[] {1, 'f'}, n.getLabel(5)));
            assertEquals("f", n.getLabelString(5));
            assertTrue(Arrays.equals(new byte[] {0}, n.getLabel(6)));
            assertEquals("", n.getLabelString(6));
        }

        public
        void test_ctor_8label() throws TextParseException {
            // 7 is the number of label positions that are cached
            Name n = new Name("a.b.c.d.e.f.g.", null);
            assertTrue(n.isAbsolute());
            assertFalse(n.isWild());
            assertEquals(8, n.labels());
            assertEquals(15, n.length());
            assertTrue(Arrays.equals(new byte[] {1, 'a'}, n.getLabel(0)));
            assertEquals("a", n.getLabelString(0));
            assertTrue(Arrays.equals(new byte[] {1, 'b'}, n.getLabel(1)));
            assertEquals("b", n.getLabelString(1));
            assertTrue(Arrays.equals(new byte[] {1, 'c'}, n.getLabel(2)));
            assertEquals("c", n.getLabelString(2));
            assertTrue(Arrays.equals(new byte[] {1, 'd'}, n.getLabel(3)));
            assertEquals("d", n.getLabelString(3));
            assertTrue(Arrays.equals(new byte[] {1, 'e'}, n.getLabel(4)));
            assertEquals("e", n.getLabelString(4));
            assertTrue(Arrays.equals(new byte[] {1, 'f'}, n.getLabel(5)));
            assertEquals("f", n.getLabelString(5));
            assertTrue(Arrays.equals(new byte[] {1, 'g'}, n.getLabel(6)));
            assertEquals("g", n.getLabelString(6));
            assertTrue(Arrays.equals(new byte[] {0}, n.getLabel(7)));
            assertEquals("", n.getLabelString(7));
        }

        public
        void test_ctor_removed_label() throws TextParseException, NameTooLongException {
            String pre = "prepend";
            Name stripped = new Name(Name.Companion.fromString("sub.domain.example.", null), 1);
            Name concat = new Name(pre, stripped);
            assertEquals(Name.Companion.concatenate(Name.Companion.fromString(pre, null), stripped), concat);
            assertEquals(Name.Companion.fromString(pre, stripped), concat);
            assertEquals("prepend.domain.example.", concat.toString());
        }

        public
        void test_ctor_abs_abs_origin() throws TextParseException {
            Name n = new Name(m_abs, m_abs_origin);
            assertTrue(n.isAbsolute());
            assertFalse(n.isWild());
            assertEquals(4, n.labels());
            assertEquals(17, n.length());
            assertTrue(Arrays.equals(new byte[] {3, 'W', 'W', 'W'}, n.getLabel(0)));
            assertEquals("WWW", n.getLabelString(0));
            assertTrue(Arrays.equals(new byte[] {7, 'D', 'n', 's', 'J', 'a', 'v', 'a'}, n.getLabel(1)));
            assertEquals("DnsJava", n.getLabelString(1));
            assertTrue(Arrays.equals(new byte[] {3, 'o', 'r', 'g'}, n.getLabel(2)));
            assertEquals("org", n.getLabelString(2));
            assertTrue(Arrays.equals(new byte[] {0}, n.getLabel(3)));
            assertEquals("", n.getLabelString(3));
        }

        public
        void test_ctor_abs_rel_origin() throws TextParseException {
            Name n = new Name(m_abs, m_rel_origin);
            assertTrue(n.isAbsolute());
            assertFalse(n.isWild());
            assertEquals(4, n.labels());
            assertEquals(17, n.length());
            assertTrue(Arrays.equals(new byte[] {3, 'W', 'W', 'W'}, n.getLabel(0)));
            assertEquals("WWW", n.getLabelString(0));
            assertTrue(Arrays.equals(new byte[] {7, 'D', 'n', 's', 'J', 'a', 'v', 'a'}, n.getLabel(1)));
            assertEquals("DnsJava", n.getLabelString(1));
            assertTrue(Arrays.equals(new byte[] {3, 'o', 'r', 'g'}, n.getLabel(2)));
            assertEquals("org", n.getLabelString(2));
            assertTrue(Arrays.equals(new byte[] {0}, n.getLabel(3)));
            assertEquals("", n.getLabelString(3));
        }

        public
        void test_ctor_rel_abs_origin() throws TextParseException {
            Name n = new Name(m_rel, m_abs_origin);
            assertTrue(n.isAbsolute());
            assertFalse(n.isWild());
            assertEquals(4, n.labels());
            assertEquals(18, n.length());
            assertTrue(Arrays.equals(new byte[] {3, 'W', 'W', 'W'}, n.getLabel(0)));
            assertEquals("WWW", n.getLabelString(0));
            assertTrue(Arrays.equals(new byte[] {7, 'D', 'n', 's', 'J', 'a', 'v', 'a'}, n.getLabel(1)));
            assertEquals("DnsJava", n.getLabelString(1));
            assertTrue(Arrays.equals(new byte[] {4, 'O', 'r', 'i', 'g'}, n.getLabel(2)));
            assertEquals("Orig", n.getLabelString(2));
            assertTrue(Arrays.equals(new byte[] {0}, n.getLabel(3)));
            assertEquals("", n.getLabelString(3));
        }

        public
        void test_ctor_invalid_label() {
            try {
                new Name("junk..junk.", null);
                fail("TextParseException not thrown");
            } catch (TextParseException e) {
            }
        }

        public
        void test_ctor_max_label() throws TextParseException {
            // name with a 63 char label
            Name n = new Name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b.", null);
            assertTrue(n.isAbsolute());
            assertFalse(n.isWild());
            assertEquals(3, n.labels());
            assertEquals(67, n.length());
            assertTrue(Arrays.equals(new byte[] {63, 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
                                                 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
                                                 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
                                                 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a'}, n.getLabel(0)));
            assertEquals("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", n.getLabelString(0));
            assertTrue(Arrays.equals(new byte[] {1, 'b'}, n.getLabel(1)));
            assertEquals("b", n.getLabelString(1));
            assertTrue(Arrays.equals(new byte[] {0}, n.getLabel(2)));
            assertEquals("", n.getLabelString(2));
        }

        public
        void test_ctor_toobig_label() {
            // name with a 64 char label
            try {
                new Name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b.", null);
                fail("TextParseException not thrown");
            } catch (TextParseException e) {
            }
        }

        public
        void test_ctor_max_length_rel() throws TextParseException {
            // relative name with three 63-char labels and a 62-char label
            Name n = new Name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", null);
            assertFalse(n.isAbsolute());
            assertFalse(n.isWild());
            assertEquals(4, n.labels());
            assertEquals(255, n.length());
        }

        public
        void test_ctor_max_length_abs() throws TextParseException {
            // absolute name with three 63-char labels and a 61-char label
            Name n = new Name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.", null);
            assertTrue(n.isAbsolute());
            assertFalse(n.isWild());
            assertEquals(5, n.labels());
            assertEquals(255, n.length());
        }

        public
        void test_ctor_escaped() throws TextParseException {
            Name n = new Name("ab\\123cd", null);
            assertFalse(n.isAbsolute());
            assertFalse(n.isWild());
            assertEquals(1, n.labels());
            assertEquals(6, n.length());
            assertTrue(Arrays.equals(new byte[] {5, 'a', 'b', (byte) 123, 'c', 'd'}, n.getLabel(0)));
        }

        public
        void test_ctor_escaped_end() throws TextParseException {
            Name n = new Name("abcd\\123", null);
            assertFalse(n.isAbsolute());
            assertFalse(n.isWild());
            assertEquals(1, n.labels());
            assertEquals(6, n.length());
            assertTrue(Arrays.equals(new byte[] {5, 'a', 'b', 'c', 'd', (byte) 123}, n.getLabel(0)));
        }

        public
        void test_ctor_short_escaped() throws TextParseException {
            try {
                new Name("ab\\12cd", null);
                fail("TextParseException not throw");
            } catch (TextParseException e) {
            }
        }

        public
        void test_ctor_short_escaped_end() throws TextParseException {
            try {
                new Name("ab\\12", null);
                fail("TextParseException not throw");
            } catch (TextParseException e) {
            }
        }

        public
        void test_ctor_empty_escaped_end() throws TextParseException {
            try {
                new Name("ab\\", null);
                fail("TextParseException not throw");
            } catch (TextParseException e) {
            }
        }

        public
        void test_ctor_toobig_escaped() throws TextParseException {
            try {
                new Name("ab\\256cd", null);
                fail("TextParseException not throw");
            } catch (TextParseException e) {
            }
        }

        public
        void test_ctor_toobig_escaped_end() throws TextParseException {
            try {
                new Name("ab\\256", null);
                fail("TextParseException not throw");
            } catch (TextParseException e) {
            }
        }

        public
        void test_ctor_max_label_escaped() throws TextParseException {
            // name with a 63 char label containing an escape
            Name n = new Name("aaaa\\100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b.", null);
            assertTrue(n.isAbsolute());
            assertFalse(n.isWild());
            assertEquals(3, n.labels());
            assertEquals(67, n.length());
            assertTrue(Arrays.equals(new byte[] {63, 'a', 'a', 'a', 'a', (byte) 100, 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
                                                 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
                                                 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
                                                 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a'}, n.getLabel(0)));
            assertTrue(Arrays.equals(new byte[] {1, 'b'}, n.getLabel(1)));
            assertEquals("b", n.getLabelString(1));
            assertTrue(Arrays.equals(new byte[] {0}, n.getLabel(2)));
            assertEquals("", n.getLabelString(2));
        }

        public
        void test_ctor_max_labels() throws TextParseException {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 127; ++i) {
                sb.append("a.");
            }
            Name n = new Name(sb.toString(), null);
            assertTrue(n.isAbsolute());
            assertFalse(n.isWild());
            assertEquals(128, n.labels());
            assertEquals(255, n.length());
            for (int i = 0; i < 127; ++i) {
                assertTrue(Arrays.equals(new byte[] {1, 'a'}, n.getLabel(i)));
                assertEquals("a", n.getLabelString(i));
            }
            assertTrue(Arrays.equals(new byte[] {0}, n.getLabel(127)));
            assertEquals("", n.getLabelString(127));
        }

        public
        void test_ctor_toobig_label_escaped_end() throws TextParseException {
            try {
                // name with a 64 char label containing an escape at the end
                new Name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\090.b.", null);
                fail("TextParseException not thrown");
            } catch (TextParseException e) {
            }
        }

        public
        void test_ctor_toobig_label_escaped() throws TextParseException {
            try {
                // name with a 64 char label containing an escape at the end
                new Name("aaaaaaaaaaaaaaaaaaaaaaaaaaaa\\001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b.", null);
                fail("TextParseException not thrown");
            } catch (TextParseException e) {
            }
        }

        public
        void test_fromString() throws TextParseException {
            Name n = new Name(m_rel, m_abs_origin);
            Name n2 = Name.Companion.fromString(m_rel, m_abs_origin);
            assertEquals(n, n2);
        }

        public
        void test_fromString_at() throws TextParseException {
            Name n = Name.Companion.fromString("@", m_rel_origin);
            assertSame(m_rel_origin, n);
        }

        public
        void test_fromString_dot() throws TextParseException {
            Name n = Name.Companion.fromString(".", null);
            assertSame(Name.getRoot(), n);
        }

        public
        void test_fromConstantString() throws TextParseException {
            Name n = new Name(m_abs, null);
            Name n2 = Name.Companion.fromConstantString(m_abs);
            assertEquals(n, n2);
        }

        public
        void test_fromConstantString_invalid() {
            try {
                Name.Companion.fromConstantString("junk..junk");
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException e) {
            }
        }
    }


    public static
    class Test_DNSInput_init extends TestCase {
        public
        void test_basic() throws IOException, TextParseException, WireParseException {

            final byte[] raw = new byte[] {3, 'W', 'w', 'w', 7, 'D', 'n', 's', 'J', 'a', 'v', 'a', 3, 'o', 'r', 'g', 0};
            Name e = Name.Companion.fromString("Www.DnsJava.org.", null);

            Name n = new Name(raw);
            assertEquals(e, n);
        }

        public
        void test_incomplete() throws IOException {
            try {
                new Name(new byte[] {3, 'W', 'w', 'w'});
                fail("WireParseException not thrown");
            } catch (WireParseException e) {
            }
        }

        public
        void test_root() throws WireParseException {
            final byte[] raw = new byte[] {0};
            Name n = new Name(new DnsInput(raw));
            assertEquals(Name.getRoot(), n);
        }

        public
        void test_invalid_length() throws IOException {
            try {
                new Name(new byte[] {4, 'W', 'w', 'w'});
                fail("WireParseException not thrown");
            } catch (WireParseException e) {
            }
        }

        public
        void test_max_label_length() throws TextParseException, WireParseException {
            byte[] raw = new byte[] {63, 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
                                     'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
                                     'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
                                     'b', 'b', 'b', 0};
            Name e = Name.Companion.fromString("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.", null);

            Name n = new Name(new DnsInput(raw));
            assertEquals(e, n);
        }

        public
        void test_max_name() throws TextParseException, WireParseException {
            // absolute name with three 63-char labels and a 61-char label
            Name e = new Name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.", null);
            byte[] raw = new byte[] {63, 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
                                     'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
                                     'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
                                     'a', 'a', 'a', 63, 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
                                     'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
                                     'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
                                     'b', 'b', 'b', 'b', 'b', 'b', 63, 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
                                     'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
                                     'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
                                     'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 61, 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
                                     'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
                                     'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
                                     'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 0};

            Name n = new Name(new DnsInput(raw));
            assertEquals(e, n);
        }

        public
        void test_toolong_name() throws TextParseException, WireParseException {
            // absolute name with three 63-char labels and a 62-char label
            byte[] raw = new byte[] {63, 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
                                     'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
                                     'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
                                     'a', 'a', 'a', 63, 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
                                     'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
                                     'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b',
                                     'b', 'b', 'b', 'b', 'b', 'b', 63, 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
                                     'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
                                     'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c',
                                     'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 'c', 62, 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
                                     'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
                                     'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd',
                                     'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 'd', 0};

            try {
                new Name(new DnsInput(raw));
                fail("WireParseException not thrown");
            } catch (WireParseException e) {
            }
        }

        public
        void test_max_labels() throws TextParseException, WireParseException {
            byte[] raw = new byte[] {1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
                                     1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
                                     1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
                                     1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
                                     1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
                                     1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
                                     1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
                                     1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
                                     1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
                                     1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 0};
            Name e = Name.Companion.fromString(
                    "a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.", null);
            Name n = new Name(new DnsInput(raw));
            assertEquals(128, n.labels());
            assertEquals(e, n);
        }

        public
        void test_toomany_labels() throws TextParseException, WireParseException {
            byte[] raw = new byte[] {1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
                                     1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
                                     1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
                                     1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
                                     1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
                                     1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
                                     1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
                                     1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
                                     1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a',
                                     1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 1, 'a', 0};
            try {
                new Name(new DnsInput(raw));
                fail("WireParseException not thrown");
            } catch (WireParseException e) {
            }
        }

        public
        void test_basic_compression() throws TextParseException, WireParseException {
            byte[] raw = new byte[] {10, 3, 'a', 'b', 'c', 0, (byte) 0xC0, 1};
            Name e = Name.Companion.fromString("abc.");

            DnsInput in = new DnsInput(raw);
            in.jump(6);

            Options.INSTANCE.set("verbosecompression");
            Name n = new Name(in);
            Options.unset("verbosecompression");
            assertEquals(e, n);
        }

        public
        void test_two_pointer_compression() throws TextParseException, WireParseException {
            byte[] raw = new byte[] {10, 3, 'a', 'b', 'c', 0, (byte) 0xC0, 1, (byte) 0xC0, 6};
            Name e = Name.Companion.fromString("abc.");

            DnsInput in = new DnsInput(raw);
            in.jump(8);

            Name n = new Name(in);
            assertEquals(e, n);
        }

        public
        void test_two_part_compression() throws TextParseException, WireParseException {
            byte[] raw = new byte[] {10, 3, 'a', 'b', 'c', 0, 1, 'B', (byte) 0xC0, 1};
            Name e = Name.Companion.fromString("B.abc.", null);

            DnsInput in = new DnsInput(raw);
            in.jump(6);

            Name n = new Name(in);
            assertEquals(e, n);
        }

        public
        void test_long_jump_compression() throws TextParseException, WireParseException {
            // pointer to name beginning at index 256
            byte[] raw = new byte[] {12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
                                     12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
                                     12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
                                     12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
                                     12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
                                     12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
                                     12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
                                     12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
                                     12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
                                     12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 3, 'a', 'b',
                                     'c', 0, (byte) 0xC1, 0};
            Name e = Name.Companion.fromString("abc.", null);

            DnsInput in = new DnsInput(raw);
            in.jump(261);
            Name n = new Name(in);
            assertEquals(e, n);
        }

        public
        void test_bad_compression() throws TextParseException, WireParseException {
            byte[] raw = new byte[] {(byte) 0xC0, 2, 0};
            try {
                new Name(new DnsInput(raw));
                fail("WireParseException not thrown");
            } catch (WireParseException e) {
            }
        }

        public
        void test_basic_compression_state_restore() throws TextParseException, WireParseException {
            byte[] raw = new byte[] {10, 3, 'a', 'b', 'c', 0, (byte) 0xC0, 1, 3, 'd', 'e', 'f', 0};
            Name e = Name.Companion.fromString("abc.", null);
            Name e2 = Name.Companion.fromString("def.");

            DnsInput in = new DnsInput(raw);
            in.jump(6);

            Name n = new Name(in);
            assertEquals(e, n);

            n = new Name(in);
            assertEquals(e2, n);
        }

        public
        void test_two_part_compression_state_restore() throws TextParseException, WireParseException {
            byte[] raw = new byte[] {10, 3, 'a', 'b', 'c', 0, 1, 'B', (byte) 0xC0, 1, 3, 'd', 'e', 'f', 0};
            Name e = Name.Companion.fromString("B.abc.");
            Name e2 = Name.Companion.fromString("def.");

            DnsInput in = new DnsInput(raw);
            in.jump(6);

            Name n = new Name(in);
            assertEquals(e, n);

            n = new Name(in);
            assertEquals(e2, n);
        }
    }

    public
    void test_init_from_name() throws TextParseException {
        Name n = new Name("A.B.c.d.");
        Name e = new Name("B.c.d.");
        Name o = new Name(n, 1);
        assertEquals(e, o);
    }

    public
    void test_init_from_name_root() throws TextParseException {
        Name n = new Name("A.B.c.d.");
        Name o = new Name(n, 4);
        assertEquals(Name.getRoot(), o);
    }

    public
    void test_init_from_name_empty() throws TextParseException {
        Name n = new Name("A.B.c.d.");
        Name n2 = new Name(n, 5);

        assertFalse(n2.isAbsolute());
        assertFalse(n2.isWild());
        assertEquals(0, n2.labels());
        assertEquals(0, n2.length());
    }

    public
    void test_concatenate_basic() throws NameTooLongException, TextParseException {
        Name p = Name.Companion.fromString("A.B");
        Name s = Name.Companion.fromString("c.d.");
        Name e = Name.Companion.fromString("A.B.c.d.");

        Name n = Name.Companion.concatenate(p, s);
        assertEquals(e, n);
    }

    public
    void test_concatenate_abs_prefix() throws NameTooLongException, TextParseException {
        Name p = Name.Companion.fromString("A.B.");
        Name s = Name.Companion.fromString("c.d.");
        Name e = Name.Companion.fromString("A.B.");

        Name n = Name.Companion.concatenate(p, s);
        assertEquals(e, n);
    }

    public
    void test_concatenate_too_long() throws TextParseException {
        Name p = Name.Companion.fromString(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        Name s = Name.Companion.fromString(
                "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.");

        try {
            Name.Companion.concatenate(p, s);
            fail("NameTooLongException not thrown");
        } catch (NameTooLongException e) {
        }
    }

    public
    void test_relativize() throws TextParseException {
        Name sub = Name.Companion.fromString("a.b.c.");
        Name dom = Name.Companion.fromString("c.");
        Name exp = Name.Companion.fromString("a.b");

        Name n = sub.relativize(dom);
        assertEquals(exp, n);
    }

    public
    void test_relativize_null_origin() throws TextParseException {
        Name sub = Name.Companion.fromString("a.b.c.");
        Name dom = null;

        Name n = sub.relativize(dom);
        assertEquals(sub, n);
    }

    public
    void test_relativize_disjoint() throws TextParseException {
        Name sub = Name.Companion.fromString("a.b.c.");
        Name dom = Name.Companion.fromString("e.f.");

        Name n = sub.relativize(dom);
        assertEquals(sub, n);
    }

    public
    void test_relativize_root() throws TextParseException {
        Name sub = Name.Companion.fromString("a.b.c.");
        Name dom = Name.Companion.fromString(".");
        Name exp = Name.Companion.fromString("a.b.c");

        Name n = sub.relativize(dom);
        assertEquals(exp, n);
    }

    public
    void test_wild() throws TextParseException {
        Name sub = Name.Companion.fromString("a.b.c.");
        Name exp = Name.Companion.fromString("*.b.c.");

        Name n = sub.wild(1);
        assertEquals(exp, n);
    }

    public
    void test_parent() throws TextParseException {
        Name dom = Name.Companion.fromString("a.b.c.");
        Name exp = Name.Companion.fromString("b.c.");

        Name n = dom.parent(1);
        assertEquals(exp, n);
    }

    public
    void test_wild_abs() throws TextParseException {
        Name sub = Name.Companion.fromString("a.b.c.");
        Name exp = Name.Companion.fromString("*.");

        Name n = sub.wild(3);
        assertEquals(exp, n);
    }

    public
    void test_wild_toobig() throws TextParseException {
        Name sub = Name.Companion.fromString("a.b.c.");
        try {
            sub.wild(4);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    public
    void test_wild_toosmall() throws TextParseException {
        Name sub = Name.Companion.fromString("a.b.c.");
        try {
            sub.wild(0);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    public
    void test_fromDNAME() throws NameTooLongException, TextParseException {
        Name own = new Name("the.owner.");
        Name alias = new Name("the.alias.");
        DNAMERecord dnr = new DNAMERecord(own, DnsClass.IN, 0xABCD, alias);
        Name sub = new Name("sub.the.owner.");
        Name exp = new Name("sub.the.alias.");

        Name n = sub.fromDNAME(dnr);
        assertEquals(exp, n);
    }

    public
    void test_fromDNAME_toobig() throws NameTooLongException, TextParseException {
        Name own = new Name("the.owner.", null);
        Name alias = new Name("the.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.", null);
        DNAMERecord dnr = new DNAMERecord(own, DnsClass.IN, 0xABCD, alias);
        Name sub = new Name("ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.the.owner.", null);

        try {
            sub.fromDNAME(dnr);
            fail("NameTooLongException not thrown");
        } catch (NameTooLongException e) {
        }
    }

    public
    void test_fromDNAME_disjoint() throws NameTooLongException, TextParseException {
        Name own = new Name("the.owner.", null);
        Name alias = new Name("the.alias.", null);
        DNAMERecord dnr = new DNAMERecord(own, DnsClass.IN, 0xABCD, alias);

        Name sub = new Name("sub.the.other", null);

        assertNull(sub.fromDNAME(dnr));
    }

    public
    void test_subdomain_abs() throws TextParseException {
        Name dom = new Name("the.domain.", null);
        Name sub = new Name("sub.of.the.domain.", null);
        assertTrue(sub.subdomain(dom));
        assertFalse(dom.subdomain(sub));
    }

    public
    void test_subdomain_rel() throws TextParseException {
        Name dom = new Name("the.domain", null);
        Name sub = new Name("sub.of.the.domain", null);
        assertTrue(sub.subdomain(dom));
        assertFalse(dom.subdomain(sub));
    }

    public
    void test_subdomain_equal() throws TextParseException {
        Name dom = new Name("the.domain", null);
        Name sub = new Name("the.domain", null);
        assertTrue(sub.subdomain(dom));
        assertTrue(dom.subdomain(sub));
    }

    public
    void test_toString_abs() throws TextParseException {
        String in = "This.Is.My.Absolute.Name.";
        Name n = new Name(in, null);

        assertEquals(in, n.toString());
    }

    public
    void test_toString_rel() throws TextParseException {
        String in = "This.Is.My.Relative.Name";
        Name n = new Name(in, null);

        assertEquals(in, n.toString());
    }

    public
    void test_toString_at() throws TextParseException {
        Name n = new Name("@", null);
        assertEquals("@", n.toString());
    }

    public
    void test_toString_root() throws TextParseException {
        assertEquals(".", Name.getRoot().toString());
    }

    public
    void test_toString_wild() throws TextParseException {
        String in = "*.A.b.c.e";
        Name n = new Name(in, null);
        assertEquals(in, n.toString());
    }

    public
    void test_toString_escaped() throws TextParseException {
        String in = "my.escaped.junk\\128.label.";
        Name n = new Name(in, null);
        assertEquals(in, n.toString());
    }

    public
    void test_toString_special_char() throws TextParseException, WireParseException {
        byte[] raw = new byte[] {1, '"', 1, '(', 1, ')', 1, '.', 1, ';', 1, '\\', 1, '@', 1, '$', 0};
        String exp = "\\\".\\(.\\).\\..\\;.\\\\.\\@.\\$.";
        Name n = new Name(new DnsInput(raw));
        assertEquals(exp, n.toString());
    }

    public static
    class Test_toWire extends TestCase {
        public
        void test_rel() throws TextParseException {
            Name n = new Name("A.Relative.Name", null);
            try {
                n.toWire(new DnsOutput(), null);
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException e) {
            }
        }

        public
        void test_null_Compression() throws TextParseException {
            byte[] raw = new byte[] {1, 'A', 5, 'B', 'a', 's', 'i', 'c', 4, 'N', 'a', 'm', 'e', 0};
            Name n = new Name("A.Basic.Name.", null);

            DnsOutput o = new DnsOutput();
            n.toWire(o, null);

            assertTrue(Arrays.equals(raw, o.toByteArray()));
        }

        public
        void test_empty_Compression() throws TextParseException {
            byte[] raw = new byte[] {1, 'A', 5, 'B', 'a', 's', 'i', 'c', 4, 'N', 'a', 'm', 'e', 0};
            Name n = new Name("A.Basic.Name.", null);

            Compression c = new Compression();
            DnsOutput o = new DnsOutput();
            n.toWire(o, c);

            assertTrue(Arrays.equals(raw, o.toByteArray()));
            assertEquals(0, c.get(n));
        }

        public
        void test_with_exact_Compression() throws TextParseException {
            Name n = new Name("A.Basic.Name.", null);

            Compression c = new Compression();
            c.add(256, n);
            byte[] exp = new byte[] {(byte) 0xC1, 0x0};

            DnsOutput o = new DnsOutput();
            n.toWire(o, c);
            assertTrue(Arrays.equals(exp, o.toByteArray()));
            assertEquals(256, c.get(n));
        }

        public
        void test_with_partial_Compression() throws TextParseException {
            Name d = new Name("Basic.Name.", null);
            Name n = new Name("A.Basic.Name.", null);

            Compression c = new Compression();
            c.add(257, d);
            byte[] exp = new byte[] {1, 'A', (byte) 0xC1, 0x1};

            DnsOutput o = new DnsOutput();
            n.toWire(o, c);
            assertTrue(Arrays.equals(exp, o.toByteArray()));
            assertEquals(257, c.get(d));
            assertEquals(0, c.get(n));
        }

        public
        void test_0arg_rel() throws TextParseException {
            Name n = new Name("A.Relative.Name", null);
            try {
                n.toWire();
                fail("IllegalArgumentException not thrown");
            } catch (IllegalArgumentException e) {
            }
        }

        public
        void test_0arg() throws TextParseException {
            byte[] raw = new byte[] {1, 'A', 5, 'B', 'a', 's', 'i', 'c', 4, 'N', 'a', 'm', 'e', 0};
            Name n = new Name("A.Basic.Name.", null);

            byte[] out = n.toWire();

            assertTrue(Arrays.equals(raw, out));
        }

        public
        void test_root() {
            byte[] out = Name.getRoot().toWire();
            assertTrue(Arrays.equals(new byte[] {0}, out));
        }

        public
        void test_3arg() throws TextParseException {
            Name d = new Name("Basic.Name.", null);
            Name n = new Name("A.Basic.Name.", null);

            Compression c = new Compression();
            c.add(257, d);
            byte[] exp = new byte[] {1, 'A', (byte) 0xC1, 0x1};

            DnsOutput o = new DnsOutput();
            n.toWire(o, c, false);
            assertTrue(Arrays.equals(exp, o.toByteArray()));
            assertEquals(257, c.get(d));
            assertEquals(0, c.get(n));
        }
    }


    public static
    class Test_toWireCanonical extends TestCase {
        public
        void test_basic() throws TextParseException {
            byte[] raw = new byte[] {1, 'a', 5, 'b', 'a', 's', 'i', 'c', 4, 'n', 'a', 'm', 'e', 0};
            Name n = new Name("A.Basic.Name.", null);

            DnsOutput o = new DnsOutput();
            n.toWireCanonical(o);

            assertTrue(Arrays.equals(raw, o.toByteArray()));
        }

        public
        void test_0arg() throws TextParseException {
            byte[] raw = new byte[] {1, 'a', 5, 'b', 'a', 's', 'i', 'c', 4, 'n', 'a', 'm', 'e', 0};
            Name n = new Name("A.Basic.Name.", null);

            byte[] out = n.toWireCanonical();

            assertTrue(Arrays.equals(raw, out));
        }

        public
        void test_root() {
            byte[] out = Name.getRoot().toWireCanonical();
            assertTrue(Arrays.equals(new byte[] {0}, out));
        }

        public
        void test_empty() throws TextParseException {
            Name n = new Name("@", null);
            byte[] out = n.toWireCanonical();
            assertTrue(Arrays.equals(new byte[0], out));
        }

        public
        void test_3arg() throws TextParseException {
            Name d = new Name("Basic.Name.", null);
            Name n = new Name("A.Basic.Name.", null);

            Compression c = new Compression();
            c.add(257, d);
            byte[] exp = new byte[] {1, 'a', 5, 'b', 'a', 's', 'i', 'c', 4, 'n', 'a', 'm', 'e', 0};

            DnsOutput o = new DnsOutput();
            n.toWire(o, c, true);
            assertTrue(Arrays.equals(exp, o.toByteArray()));
            assertEquals(257, c.get(d));
            assertEquals(-1, c.get(n));
        }
    }


    public static
    class Test_equals extends TestCase {
        public
        void test_same() throws TextParseException {
            Name n = new Name("A.Name.", null);
            assertTrue(n.equals(n));
        }

        public
        void test_null() throws TextParseException {
            Name n = new Name("A.Name.", null);
            assertFalse(n.equals(null));
        }

        public
        void test_notName() throws TextParseException {
            Name n = new Name("A.Name.", null);
            assertFalse(n.equals(new Object()));
        }

        public
        void test_abs() throws TextParseException {
            Name n = new Name("A.Name.", null);
            Name n2 = new Name("a.name.", null);

            assertTrue(n.equals(n2));
            assertTrue(n2.equals(n));
        }

        public
        void test_rel() throws TextParseException {
            Name n1 = new Name("A.Relative.Name", null);
            Name n2 = new Name("a.relative.name", null);

            assertTrue(n1.equals(n2));
            assertTrue(n2.equals(n1));
        }

        public
        void test_mixed() throws TextParseException {
            Name n1 = new Name("A.Name", null);
            Name n2 = new Name("a.name.", null);

            assertFalse(n1.equals(n2));
            assertFalse(n2.equals(n1));
        }

        public
        void test_weird() throws TextParseException {
            Name n1 = new Name("ab.c", null);
            Name n2 = new Name("abc.", null);

            assertFalse(n1.equals(n2));
            assertFalse(n2.equals(n1));
        }
    }


    public static
    class Test_compareTo extends TestCase {
        public
        void test_notName() throws TextParseException {
            Name n = new Name("A.Name", null);
            try {
                n.compareTo(new Object());
                fail("ClassCastException not thrown");
            } catch (ClassCastException e) {
            }
        }

        public
        void test_same() throws TextParseException {
            Name n = new Name("A.Name", null);
            assertEquals(0, n.compareTo(n));
        }

        public
        void test_equal() throws TextParseException {
            Name n1 = new Name("A.Name.", null);
            Name n2 = new Name("a.name.", null);

            assertEquals(0, n1.compareTo(n2));
            assertEquals(0, n2.compareTo(n1));
        }

        public
        void test_close() throws TextParseException {
            Name n1 = new Name("a.name", null);
            Name n2 = new Name("a.name.", null);

            assertTrue(n1.compareTo(n2) > 0);
            assertTrue(n2.compareTo(n1) < 0);
        }

        public
        void test_disjoint() throws TextParseException {
            Name n1 = new Name("b", null);
            Name n2 = new Name("c", null);

            assertTrue(n1.compareTo(n2) < 0);
            assertTrue(n2.compareTo(n1) > 0);
        }

        public
        void test_label_prefix() throws TextParseException {
            Name n1 = new Name("thisIs.a.", null);
            Name n2 = new Name("thisIsGreater.a.", null);

            assertTrue(n1.compareTo(n2) < 0);
            assertTrue(n2.compareTo(n1) > 0);
        }

        public
        void test_more_labels() throws TextParseException {
            Name n1 = new Name("c.b.a.", null);
            Name n2 = new Name("d.c.b.a.", null);

            assertTrue(n1.compareTo(n2) < 0);
            assertTrue(n2.compareTo(n1) > 0);
        }
    }

    public
    void test_canonicalize() throws TextParseException {
        Name n1 = new Name("ABC.com", null);
        Name n2 = new Name("abc.com", null);
        Name n3 = new Name("\\193.com", null);

        Name cn1 = n1.canonicalize();
        Name cn2 = n2.canonicalize();
        Name cn3 = n3.canonicalize();

        assertNotSame(n1, cn1);
        assertEquals(n1, cn1);
        assertSame(n2, cn2);
        assertSame(n3, cn3);
        assertEquals(cn1.toString(), cn2.toString());
        assertFalse(n1.toString()
                      .equals(n2.toString()));
        assertEquals(cn1.toString(), cn2.toString());
    }

    public
    void test_to_string() throws TextParseException {
        Name n1 = new Name("abc.com");
        Name n2 = new Name("abc.com.");

        assertEquals(n1.toString(true), n1.toString(true));
        assertFalse(n2.toString(true).equals(n2.toString(false)));

        assertEquals(n2.toString(true) + ".", n2.toString(false));
        assertEquals(Name.getRoot().toString(true), Name.getRoot().toString(false));
        assertEquals(Name.getEmpty().toString(true), Name.getEmpty().toString(false));
    }

    public
    void test_absolute() throws TextParseException {
        Name n1 = new Name("abc.com", null);
        Name n2 = new Name("abc.com.", null);
        Name n3 = new Name("abc.com", Name.getRoot());
        Name n4 = new Name("abc.com", n1);
        Name n5 = new Name("abc.com\\000", null);

        assertFalse(n1.isAbsolute());
        assertTrue(n2.isAbsolute());
        assertTrue(n3.isAbsolute());
        assertFalse(n4.isAbsolute());
        assertFalse(n5.isAbsolute());
    }

    public static
    Test suite() {
        TestSuite s = new TestSuite();
        s.addTestSuite(Test_String_init.class);
        s.addTestSuite(Test_DNSInput_init.class);
        s.addTestSuite(NameTest.class);
        s.addTestSuite(Test_toWire.class);
        s.addTestSuite(Test_toWireCanonical.class);
        s.addTestSuite(Test_equals.class);
        s.addTestSuite(Test_compareTo.class);
        return s;
    }
}
