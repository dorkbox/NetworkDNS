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

import dorkbox.dns.dns.Name.Companion.concatenate
import dorkbox.dns.dns.Name.Companion.empty
import dorkbox.dns.dns.Name.Companion.fromConstantString
import dorkbox.dns.dns.Name.Companion.fromString
import dorkbox.dns.dns.Name.Companion.root
import dorkbox.dns.dns.constants.DnsClass
import dorkbox.dns.dns.exceptions.NameTooLongException
import dorkbox.dns.dns.exceptions.TextParseException
import dorkbox.dns.dns.exceptions.WireParseException
import dorkbox.dns.dns.records.DNAMERecord
import dorkbox.dns.dns.utils.Options.set
import dorkbox.dns.dns.utils.Options.unset
import junit.framework.Test
import junit.framework.TestCase
import junit.framework.TestSuite
import java.io.IOException
import java.util.*

class NameTest : TestCase() {
    class Test_String_init : TestCase() {
        private val m_abs = "WWW.DnsJava.org."
        private var m_abs_origin: Name? = null
        private val m_rel = "WWW.DnsJava"
        private var m_rel_origin: Name? = null


        override fun setUp() {
            m_abs_origin = fromString("Orig.", null)
            m_rel_origin = fromString("Orig", null)
        }

        fun test_ctor_empty() {
            try {
                Name("", null)
                fail("TextParseException not thrown")
            } catch (ignored: TextParseException) {
            }
        }

        @Throws(TextParseException::class)
        fun test_ctor_at_null_origin() {
            val n = Name("@", null)
            assertFalse(n.isAbsolute)
            assertFalse(n.isWild)
            assertEquals(0, n.labels())
            assertEquals(0, n.length().toInt())
        }

        @Throws(TextParseException::class)
        fun test_ctor_at_abs_origin() {
            val n = Name("@", m_abs_origin)
            assertEquals(m_abs_origin, n)
        }

        @Throws(TextParseException::class)
        fun test_ctor_at_rel_origin() {
            val n = Name("@", m_rel_origin)
            assertEquals(m_rel_origin, n)
        }

        @Throws(TextParseException::class)
        fun test_ctor_dot() {
            val n = Name(".", null)
            assertEquals(root, n)
            assertNotSame(root, n)
            assertEquals(1, n.labels())
            assertEquals(1, n.length().toInt())
        }

        @Throws(TextParseException::class)
        fun test_ctor_wildcard() {
            val n = Name("*", null)
            assertFalse(n.isAbsolute)
            assertTrue(n.isWild)
            assertEquals(1, n.labels())
            assertEquals(2, n.length().toInt())
            assertTrue(Arrays.equals(byteArrayOf(1, '*'.code.toByte()), n.getLabel(0)))
            assertEquals("*", n.getLabelString(0))
        }

        @Throws(TextParseException::class)
        fun test_ctor_abs() {
            val n = Name(m_abs, null)
            assertTrue(n.isAbsolute)
            assertFalse(n.isWild)
            assertEquals(4, n.labels())
            assertEquals(17, n.length().toInt())
            assertTrue(Arrays.equals(byteArrayOf(3, 'W'.code.toByte(), 'W'.code.toByte(), 'W'.code.toByte()), n.getLabel(0)))
            assertEquals("WWW", n.getLabelString(0))
            assertTrue(
                Arrays.equals(
                    byteArrayOf(
                        7,
                        'D'.code.toByte(),
                        'n'.code.toByte(),
                        's'.code.toByte(),
                        'J'.code.toByte(),
                        'a'.code.toByte(),
                        'v'.code.toByte(),
                        'a'.code.toByte()
                    ), n.getLabel(1)
                )
            )
            assertEquals("DnsJava", n.getLabelString(1))
            assertTrue(Arrays.equals(byteArrayOf(3, 'o'.code.toByte(), 'r'.code.toByte(), 'g'.code.toByte()), n.getLabel(2)))
            assertEquals("org", n.getLabelString(2))
            assertTrue(Arrays.equals(byteArrayOf(0), n.getLabel(3)))
            assertEquals("", n.getLabelString(3))
        }

        @Throws(TextParseException::class)
        fun test_ctor_rel() {
            val n = Name(m_rel, null)
            assertFalse(n.isAbsolute)
            assertFalse(n.isWild)
            assertEquals(2, n.labels())
            assertEquals(12, n.length().toInt())
            assertTrue(Arrays.equals(byteArrayOf(3, 'W'.code.toByte(), 'W'.code.toByte(), 'W'.code.toByte()), n.getLabel(0)))
            assertEquals("WWW", n.getLabelString(0))
            assertTrue(
                Arrays.equals(
                    byteArrayOf(
                        7,
                        'D'.code.toByte(),
                        'n'.code.toByte(),
                        's'.code.toByte(),
                        'J'.code.toByte(),
                        'a'.code.toByte(),
                        'v'.code.toByte(),
                        'a'.code.toByte()
                    ), n.getLabel(1)
                )
            )
            assertEquals("DnsJava", n.getLabelString(1))
        }

        @Throws(TextParseException::class)
        fun test_ctor_7label() {
            // 7 is the number of label positions that are cached
            val n = Name("a.b.c.d.e.f.", null)
            assertTrue(n.isAbsolute)
            assertFalse(n.isWild)
            assertEquals(7, n.labels())
            assertEquals(13, n.length().toInt())
            assertTrue(Arrays.equals(byteArrayOf(1, 'a'.code.toByte()), n.getLabel(0)))
            assertEquals("a", n.getLabelString(0))
            assertTrue(Arrays.equals(byteArrayOf(1, 'b'.code.toByte()), n.getLabel(1)))
            assertEquals("b", n.getLabelString(1))
            assertTrue(Arrays.equals(byteArrayOf(1, 'c'.code.toByte()), n.getLabel(2)))
            assertEquals("c", n.getLabelString(2))
            assertTrue(Arrays.equals(byteArrayOf(1, 'd'.code.toByte()), n.getLabel(3)))
            assertEquals("d", n.getLabelString(3))
            assertTrue(Arrays.equals(byteArrayOf(1, 'e'.code.toByte()), n.getLabel(4)))
            assertEquals("e", n.getLabelString(4))
            assertTrue(Arrays.equals(byteArrayOf(1, 'f'.code.toByte()), n.getLabel(5)))
            assertEquals("f", n.getLabelString(5))
            assertTrue(Arrays.equals(byteArrayOf(0), n.getLabel(6)))
            assertEquals("", n.getLabelString(6))
        }

        @Throws(TextParseException::class)
        fun test_ctor_8label() {
            // 7 is the number of label positions that are cached
            val n = Name("a.b.c.d.e.f.g.", null)
            assertTrue(n.isAbsolute)
            assertFalse(n.isWild)
            assertEquals(8, n.labels())
            assertEquals(15, n.length().toInt())
            assertTrue(Arrays.equals(byteArrayOf(1, 'a'.code.toByte()), n.getLabel(0)))
            assertEquals("a", n.getLabelString(0))
            assertTrue(Arrays.equals(byteArrayOf(1, 'b'.code.toByte()), n.getLabel(1)))
            assertEquals("b", n.getLabelString(1))
            assertTrue(Arrays.equals(byteArrayOf(1, 'c'.code.toByte()), n.getLabel(2)))
            assertEquals("c", n.getLabelString(2))
            assertTrue(Arrays.equals(byteArrayOf(1, 'd'.code.toByte()), n.getLabel(3)))
            assertEquals("d", n.getLabelString(3))
            assertTrue(Arrays.equals(byteArrayOf(1, 'e'.code.toByte()), n.getLabel(4)))
            assertEquals("e", n.getLabelString(4))
            assertTrue(Arrays.equals(byteArrayOf(1, 'f'.code.toByte()), n.getLabel(5)))
            assertEquals("f", n.getLabelString(5))
            assertTrue(Arrays.equals(byteArrayOf(1, 'g'.code.toByte()), n.getLabel(6)))
            assertEquals("g", n.getLabelString(6))
            assertTrue(Arrays.equals(byteArrayOf(0), n.getLabel(7)))
            assertEquals("", n.getLabelString(7))
        }

        @Throws(TextParseException::class, NameTooLongException::class)
        fun test_ctor_removed_label() {
            val pre = "prepend"
            val stripped = Name(fromString("sub.domain.example.", null), 1)
            val concat = Name(pre, stripped)
            assertEquals(concatenate(fromString(pre, null), stripped), concat)
            assertEquals(fromString(pre, stripped), concat)
            assertEquals("prepend.domain.example.", concat.toString())
        }

        @Throws(TextParseException::class)
        fun test_ctor_abs_abs_origin() {
            val n = Name(m_abs, m_abs_origin)
            assertTrue(n.isAbsolute)
            assertFalse(n.isWild)
            assertEquals(4, n.labels())
            assertEquals(17, n.length().toInt())
            assertTrue(Arrays.equals(byteArrayOf(3, 'W'.code.toByte(), 'W'.code.toByte(), 'W'.code.toByte()), n.getLabel(0)))
            assertEquals("WWW", n.getLabelString(0))
            assertTrue(
                Arrays.equals(
                    byteArrayOf(
                        7,
                        'D'.code.toByte(),
                        'n'.code.toByte(),
                        's'.code.toByte(),
                        'J'.code.toByte(),
                        'a'.code.toByte(),
                        'v'.code.toByte(),
                        'a'.code.toByte()
                    ), n.getLabel(1)
                )
            )
            assertEquals("DnsJava", n.getLabelString(1))
            assertTrue(Arrays.equals(byteArrayOf(3, 'o'.code.toByte(), 'r'.code.toByte(), 'g'.code.toByte()), n.getLabel(2)))
            assertEquals("org", n.getLabelString(2))
            assertTrue(Arrays.equals(byteArrayOf(0), n.getLabel(3)))
            assertEquals("", n.getLabelString(3))
        }

        @Throws(TextParseException::class)
        fun test_ctor_abs_rel_origin() {
            val n = Name(m_abs, m_rel_origin)
            assertTrue(n.isAbsolute)
            assertFalse(n.isWild)
            assertEquals(4, n.labels())
            assertEquals(17, n.length().toInt())
            assertTrue(Arrays.equals(byteArrayOf(3, 'W'.code.toByte(), 'W'.code.toByte(), 'W'.code.toByte()), n.getLabel(0)))
            assertEquals("WWW", n.getLabelString(0))
            assertTrue(
                Arrays.equals(
                    byteArrayOf(
                        7,
                        'D'.code.toByte(),
                        'n'.code.toByte(),
                        's'.code.toByte(),
                        'J'.code.toByte(),
                        'a'.code.toByte(),
                        'v'.code.toByte(),
                        'a'.code.toByte()
                    ), n.getLabel(1)
                )
            )
            assertEquals("DnsJava", n.getLabelString(1))
            assertTrue(Arrays.equals(byteArrayOf(3, 'o'.code.toByte(), 'r'.code.toByte(), 'g'.code.toByte()), n.getLabel(2)))
            assertEquals("org", n.getLabelString(2))
            assertTrue(Arrays.equals(byteArrayOf(0), n.getLabel(3)))
            assertEquals("", n.getLabelString(3))
        }

        @Throws(TextParseException::class)
        fun test_ctor_rel_abs_origin() {
            val n = Name(m_rel, m_abs_origin)
            assertTrue(n.isAbsolute)
            assertFalse(n.isWild)
            assertEquals(4, n.labels())
            assertEquals(18, n.length().toInt())
            assertTrue(Arrays.equals(byteArrayOf(3, 'W'.code.toByte(), 'W'.code.toByte(), 'W'.code.toByte()), n.getLabel(0)))
            assertEquals("WWW", n.getLabelString(0))
            assertTrue(
                Arrays.equals(
                    byteArrayOf(
                        7,
                        'D'.code.toByte(),
                        'n'.code.toByte(),
                        's'.code.toByte(),
                        'J'.code.toByte(),
                        'a'.code.toByte(),
                        'v'.code.toByte(),
                        'a'.code.toByte()
                    ), n.getLabel(1)
                )
            )
            assertEquals("DnsJava", n.getLabelString(1))
            assertTrue(
                Arrays.equals(
                    byteArrayOf(4, 'O'.code.toByte(), 'r'.code.toByte(), 'i'.code.toByte(), 'g'.code.toByte()),
                    n.getLabel(2)
                )
            )
            assertEquals("Orig", n.getLabelString(2))
            assertTrue(Arrays.equals(byteArrayOf(0), n.getLabel(3)))
            assertEquals("", n.getLabelString(3))
        }

        fun test_ctor_invalid_label() {
            try {
                Name("junk..junk.", null)
                fail("TextParseException not thrown")
            } catch (ignored: TextParseException) {
            }
        }

        @Throws(TextParseException::class)
        fun test_ctor_max_label() {
            // name with a 63 char label
            val n = Name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b.", null)
            assertTrue(n.isAbsolute)
            assertFalse(n.isWild)
            assertEquals(3, n.labels())
            assertEquals(67, n.length().toInt())
            assertTrue(
                Arrays.equals(
                    byteArrayOf(
                        63,
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte()
                    ), n.getLabel(0)
                )
            )
            assertEquals("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", n.getLabelString(0))
            assertTrue(Arrays.equals(byteArrayOf(1, 'b'.code.toByte()), n.getLabel(1)))
            assertEquals("b", n.getLabelString(1))
            assertTrue(Arrays.equals(byteArrayOf(0), n.getLabel(2)))
            assertEquals("", n.getLabelString(2))
        }

        fun test_ctor_toobig_label() {
            // name with a 64 char label
            try {
                Name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b.", null)
                fail("TextParseException not thrown")
            } catch (ignored: TextParseException) {
            }
        }

        @Throws(TextParseException::class)
        fun test_ctor_max_length_rel() {
            // relative name with three 63-char labels and a 62-char label
            val n = Name(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                null
            )
            assertFalse(n.isAbsolute)
            assertFalse(n.isWild)
            assertEquals(4, n.labels())
            assertEquals(255, n.length().toInt())
        }

        @Throws(TextParseException::class)
        fun test_ctor_max_length_abs() {
            // absolute name with three 63-char labels and a 61-char label
            val n = Name(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.",
                null
            )
            assertTrue(n.isAbsolute)
            assertFalse(n.isWild)
            assertEquals(5, n.labels())
            assertEquals(255, n.length().toInt())
        }

        @Throws(TextParseException::class)
        fun test_ctor_escaped() {
            val n = Name("ab\\123cd", null)
            assertFalse(n.isAbsolute)
            assertFalse(n.isWild)
            assertEquals(1, n.labels())
            assertEquals(6, n.length().toInt())
            assertTrue(
                Arrays.equals(
                    byteArrayOf(
                        5,
                        'a'.code.toByte(),
                        'b'.code.toByte(),
                        123.toByte(),
                        'c'.code.toByte(),
                        'd'.code.toByte()
                    ), n.getLabel(0)
                )
            )
        }

        @Throws(TextParseException::class)
        fun test_ctor_escaped_end() {
            val n = Name("abcd\\123", null)
            assertFalse(n.isAbsolute)
            assertFalse(n.isWild)
            assertEquals(1, n.labels())
            assertEquals(6, n.length().toInt())
            assertTrue(
                Arrays.equals(
                    byteArrayOf(
                        5,
                        'a'.code.toByte(),
                        'b'.code.toByte(),
                        'c'.code.toByte(),
                        'd'.code.toByte(),
                        123.toByte()
                    ), n.getLabel(0)
                )
            )
        }

        @Throws(TextParseException::class)
        fun test_ctor_short_escaped() {
            try {
                Name("ab\\12cd", null)
                fail("TextParseException not throw")
            } catch (ignored: TextParseException) {
            }
        }

        @Throws(TextParseException::class)
        fun test_ctor_short_escaped_end() {
            try {
                Name("ab\\12", null)
                fail("TextParseException not throw")
            } catch (ignored: TextParseException) {
            }
        }

        @Throws(TextParseException::class)
        fun test_ctor_empty_escaped_end() {
            try {
                Name("ab\\", null)
                fail("TextParseException not throw")
            } catch (ignored: TextParseException) {
            }
        }

        @Throws(TextParseException::class)
        fun test_ctor_toobig_escaped() {
            try {
                Name("ab\\256cd", null)
                fail("TextParseException not throw")
            } catch (ignored: TextParseException) {
            }
        }

        @Throws(TextParseException::class)
        fun test_ctor_toobig_escaped_end() {
            try {
                Name("ab\\256", null)
                fail("TextParseException not throw")
            } catch (ignored: TextParseException) {
            }
        }

        @Throws(TextParseException::class)
        fun test_ctor_max_label_escaped() {
            // name with a 63 char label containing an escape
            val n = Name("aaaa\\100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b.", null)
            assertTrue(n.isAbsolute)
            assertFalse(n.isWild)
            assertEquals(3, n.labels())
            assertEquals(67, n.length().toInt())
            assertTrue(
                Arrays.equals(
                    byteArrayOf(
                        63,
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        100.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte(),
                        'a'.code.toByte()
                    ), n.getLabel(0)
                )
            )
            assertTrue(Arrays.equals(byteArrayOf(1, 'b'.code.toByte()), n.getLabel(1)))
            assertEquals("b", n.getLabelString(1))
            assertTrue(Arrays.equals(byteArrayOf(0), n.getLabel(2)))
            assertEquals("", n.getLabelString(2))
        }

        @Throws(TextParseException::class)
        fun test_ctor_max_labels() {
            val sb = StringBuilder()
            for (i in 0..126) {
                sb.append("a.")
            }
            val n = Name(sb.toString(), null)
            assertTrue(n.isAbsolute)
            assertFalse(n.isWild)
            assertEquals(128, n.labels())
            assertEquals(255, n.length().toInt())
            for (i in 0..126) {
                assertTrue(Arrays.equals(byteArrayOf(1, 'a'.code.toByte()), n.getLabel(i)))
                assertEquals("a", n.getLabelString(i))
            }
            assertTrue(Arrays.equals(byteArrayOf(0), n.getLabel(127)))
            assertEquals("", n.getLabelString(127))
        }

        @Throws(TextParseException::class)
        fun test_ctor_toobig_label_escaped_end() {
            try {
                // name with a 64 char label containing an escape at the end
                Name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\090.b.", null)
                fail("TextParseException not thrown")
            } catch (ignored: TextParseException) {
            }
        }

        @Throws(TextParseException::class)
        fun test_ctor_toobig_label_escaped() {
            try {
                // name with a 64 char label containing an escape at the end
                Name("aaaaaaaaaaaaaaaaaaaaaaaaaaaa\\001aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b.", null)
                fail("TextParseException not thrown")
            } catch (ignored: TextParseException) {
            }
        }

        @Throws(TextParseException::class)
        fun test_fromString() {
            val n = Name(m_rel, m_abs_origin)
            val n2 = fromString(m_rel, m_abs_origin)
            assertEquals(n, n2)
        }

        @Throws(TextParseException::class)
        fun test_fromString_at() {
            val n = fromString("@", m_rel_origin)
            assertSame(m_rel_origin, n)
        }

        @Throws(TextParseException::class)
        fun test_fromString_dot() {
            val n = fromString(".", null)
            assertSame(root, n)
        }

        @Throws(TextParseException::class)
        fun test_fromConstantString() {
            val n = Name(m_abs, null)
            val n2 = fromConstantString(m_abs)
            assertEquals(n, n2)
        }

        fun test_fromConstantString_invalid() {
            try {
                fromConstantString("junk..junk")
                fail("IllegalArgumentException not thrown")
            } catch (ignored: IllegalArgumentException) {
            }
        }
    }

    class Test_DNSInput_init : TestCase() {
        @Throws(IOException::class, TextParseException::class, WireParseException::class)
        fun test_basic() {
            val raw = byteArrayOf(
                3,
                'W'.code.toByte(),
                'w'.code.toByte(),
                'w'.code.toByte(),
                7,
                'D'.code.toByte(),
                'n'.code.toByte(),
                's'.code.toByte(),
                'J'.code.toByte(),
                'a'.code.toByte(),
                'v'.code.toByte(),
                'a'.code.toByte(),
                3,
                'o'.code.toByte(),
                'r'.code.toByte(),
                'g'.code.toByte(),
                0
            )
            val e = fromString("Www.DnsJava.org.", null)
            val n = Name(raw)
            assertEquals(e, n)
        }

        @Throws(IOException::class)
        fun test_incomplete() {
            try {
                Name(byteArrayOf(3, 'W'.code.toByte(), 'w'.code.toByte(), 'w'.code.toByte()))
                fail("WireParseException not thrown")
            } catch (e: WireParseException) {
            }
        }

        @Throws(WireParseException::class)
        fun test_root() {
            val raw = byteArrayOf(0)
            val n = Name(DnsInput(raw))
            assertEquals(root, n)
        }

        @Throws(IOException::class)
        fun test_invalid_length() {
            try {
                Name(byteArrayOf(4, 'W'.code.toByte(), 'w'.code.toByte(), 'w'.code.toByte()))
                fail("WireParseException not thrown")
            } catch (e: WireParseException) {
            }
        }

        @Throws(TextParseException::class, WireParseException::class)
        fun test_max_label_length() {
            val raw = byteArrayOf(
                63,
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                0
            )
            val e = fromString("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.", null)
            val n = Name(DnsInput(raw))
            assertEquals(e, n)
        }

        @Throws(TextParseException::class, WireParseException::class)
        fun test_max_name() {
            // absolute name with three 63-char labels and a 61-char label
            val e = Name(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.",
                null
            )
            val raw = byteArrayOf(
                63,
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                63,
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                63,
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                61,
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                0
            )
            val n = Name(DnsInput(raw))
            assertEquals(e, n)
        }

        @Throws(TextParseException::class, WireParseException::class)
        fun test_toolong_name() {
            // absolute name with three 63-char labels and a 62-char label
            val raw = byteArrayOf(
                63,
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                'a'.code.toByte(),
                63,
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                'b'.code.toByte(),
                63,
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                'c'.code.toByte(),
                62,
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                'd'.code.toByte(),
                0
            )
            try {
                Name(DnsInput(raw))
                fail("WireParseException not thrown")
            } catch (e: WireParseException) {
            }
        }

        @Throws(TextParseException::class, WireParseException::class)
        fun test_max_labels() {
            val raw = byteArrayOf(
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                0
            )
            val e = fromString(
                "a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.",
                null
            )
            val n = Name(DnsInput(raw))
            assertEquals(128, n.labels())
            assertEquals(e, n)
        }

        @Throws(TextParseException::class, WireParseException::class)
        fun test_toomany_labels() {
            val raw = byteArrayOf(
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                1,
                'a'.code.toByte(),
                0
            )
            try {
                Name(DnsInput(raw))
                fail("WireParseException not thrown")
            } catch (e: WireParseException) {
            }
        }

        @Throws(TextParseException::class, WireParseException::class)
        fun test_basic_compression() {
            val raw = byteArrayOf(10, 3, 'a'.code.toByte(), 'b'.code.toByte(), 'c'.code.toByte(), 0, 0xC0.toByte(), 1)
            val e = fromString("abc.")
            val `in` = DnsInput(raw)
            `in`.jump(6)
            set("verbosecompression")
            val n = Name(`in`)
            unset("verbosecompression")
            assertEquals(e, n)
        }

        @Throws(TextParseException::class, WireParseException::class)
        fun test_two_pointer_compression() {
            val raw = byteArrayOf(10, 3, 'a'.code.toByte(), 'b'.code.toByte(), 'c'.code.toByte(), 0, 0xC0.toByte(), 1, 0xC0.toByte(), 6)
            val e = fromString("abc.")
            val `in` = DnsInput(raw)
            `in`.jump(8)
            val n = Name(`in`)
            assertEquals(e, n)
        }

        @Throws(TextParseException::class, WireParseException::class)
        fun test_two_part_compression() {
            val raw = byteArrayOf(10, 3, 'a'.code.toByte(), 'b'.code.toByte(), 'c'.code.toByte(), 0, 1, 'B'.code.toByte(), 0xC0.toByte(), 1)
            val e = fromString("B.abc.", null)
            val `in` = DnsInput(raw)
            `in`.jump(6)
            val n = Name(`in`)
            assertEquals(e, n)
        }

        @Throws(TextParseException::class, WireParseException::class)
        fun test_long_jump_compression() {
            // pointer to name beginning at index 256
            val raw = byteArrayOf(
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                12,
                3,
                'a'.code.toByte(),
                'b'.code.toByte(),
                'c'.code.toByte(),
                0,
                0xC1.toByte(),
                0
            )
            val e = fromString("abc.", null)
            val `in` = DnsInput(raw)
            `in`.jump(261)
            val n = Name(`in`)
            assertEquals(e, n)
        }

        @Throws(TextParseException::class, WireParseException::class)
        fun test_bad_compression() {
            val raw = byteArrayOf(0xC0.toByte(), 2, 0)
            try {
                Name(DnsInput(raw))
                fail("WireParseException not thrown")
            } catch (e: WireParseException) {
            }
        }

        @Throws(TextParseException::class, WireParseException::class)
        fun test_basic_compression_state_restore() {
            val raw = byteArrayOf(
                10,
                3,
                'a'.code.toByte(),
                'b'.code.toByte(),
                'c'.code.toByte(),
                0,
                0xC0.toByte(),
                1,
                3,
                'd'.code.toByte(),
                'e'.code.toByte(),
                'f'.code.toByte(),
                0
            )
            val e = fromString("abc.", null)
            val e2 = fromString("def.")
            val `in` = DnsInput(raw)
            `in`.jump(6)
            var n = Name(`in`)
            assertEquals(e, n)
            n = Name(`in`)
            assertEquals(e2, n)
        }

        @Throws(TextParseException::class, WireParseException::class)
        fun test_two_part_compression_state_restore() {
            val raw = byteArrayOf(
                10,
                3,
                'a'.code.toByte(),
                'b'.code.toByte(),
                'c'.code.toByte(),
                0,
                1,
                'B'.code.toByte(),
                0xC0.toByte(),
                1,
                3,
                'd'.code.toByte(),
                'e'.code.toByte(),
                'f'.code.toByte(),
                0
            )
            val e = fromString("B.abc.")
            val e2 = fromString("def.")
            val `in` = DnsInput(raw)
            `in`.jump(6)
            var n = Name(`in`)
            assertEquals(e, n)
            n = Name(`in`)
            assertEquals(e2, n)
        }
    }

    @Throws(TextParseException::class)
    fun test_init_from_name() {
        val n = Name("A.B.c.d.")
        val e = Name("B.c.d.")
        val o = Name(n, 1)
        assertEquals(e, o)
    }

    @Throws(TextParseException::class)
    fun test_init_from_name_root() {
        val n = Name("A.B.c.d.")
        val o = Name(n, 4)
        assertEquals(root, o)
    }

    @Throws(TextParseException::class)
    fun test_init_from_name_empty() {
        val n = Name("A.B.c.d.")
        val n2 = Name(n, 5)
        assertFalse(n2.isAbsolute)
        assertFalse(n2.isWild)
        assertEquals(0, n2.labels())
        assertEquals(0, n2.length().toInt())
    }

    @Throws(NameTooLongException::class, TextParseException::class)
    fun test_concatenate_basic() {
        val p = fromString("A.B")
        val s = fromString("c.d.")
        val e = fromString("A.B.c.d.")
        val n = concatenate(p, s)
        assertEquals(e, n)
    }

    @Throws(NameTooLongException::class, TextParseException::class)
    fun test_concatenate_abs_prefix() {
        val p = fromString("A.B.")
        val s = fromString("c.d.")
        val e = fromString("A.B.")
        val n = concatenate(p, s)
        assertEquals(e, n)
    }

    @Throws(TextParseException::class)
    fun test_concatenate_too_long() {
        val p = fromString(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        )
        val s = fromString(
            "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd."
        )
        try {
            concatenate(p, s)
            fail("NameTooLongException not thrown")
        } catch (e: NameTooLongException) {
        }
    }

    @Throws(TextParseException::class)
    fun test_relativize() {
        val sub = fromString("a.b.c.")
        val dom = fromString("c.")
        val exp = fromString("a.b")
        val n = sub.relativize(dom)
        assertEquals(exp, n)
    }

    @Throws(TextParseException::class)
    fun test_relativize_null_origin() {
        val sub = fromString("a.b.c.")
        val dom: Name? = null
        val n = sub.relativize(dom)
        assertEquals(sub, n)
    }

    @Throws(TextParseException::class)
    fun test_relativize_disjoint() {
        val sub = fromString("a.b.c.")
        val dom = fromString("e.f.")
        val n = sub.relativize(dom)
        assertEquals(sub, n)
    }

    @Throws(TextParseException::class)
    fun test_relativize_root() {
        val sub = fromString("a.b.c.")
        val dom = fromString(".")
        val exp = fromString("a.b.c")
        val n = sub.relativize(dom)
        assertEquals(exp, n)
    }

    @Throws(TextParseException::class)
    fun test_wild() {
        val sub = fromString("a.b.c.")
        val exp = fromString("*.b.c.")
        val n = sub.wild(1)
        assertEquals(exp, n)
    }

    @Throws(TextParseException::class)
    fun test_parent() {
        val dom = fromString("a.b.c.")
        val exp = fromString("b.c.")
        val n = dom.parent(1)
        assertEquals(exp, n)
    }

    @Throws(TextParseException::class)
    fun test_wild_abs() {
        val sub = fromString("a.b.c.")
        val exp = fromString("*.")
        val n = sub.wild(3)
        assertEquals(exp, n)
    }

    @Throws(TextParseException::class)
    fun test_wild_toobig() {
        val sub = fromString("a.b.c.")
        try {
            sub.wild(4)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
    }

    @Throws(TextParseException::class)
    fun test_wild_toosmall() {
        val sub = fromString("a.b.c.")
        try {
            sub.wild(0)
            fail("IllegalArgumentException not thrown")
        } catch (ignored: IllegalArgumentException) {
        }
    }

    @Throws(NameTooLongException::class, TextParseException::class)
    fun test_fromDNAME() {
        val own = Name("the.owner.")
        val alias = Name("the.alias.")
        val dnr = DNAMERecord(own, DnsClass.IN, 0xABCD, alias)
        val sub = Name("sub.the.owner.")
        val exp = Name("sub.the.alias.")
        val n = sub.fromDNAME(dnr)
        assertEquals(exp, n)
    }

    @Throws(NameTooLongException::class, TextParseException::class)
    fun test_fromDNAME_toobig() {
        val own = Name("the.owner.", null)
        val alias = Name(
            "the.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.",
            null
        )
        val dnr = DNAMERecord(own, DnsClass.IN, 0xABCD, alias)
        val sub = Name("ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.the.owner.", null)
        try {
            sub.fromDNAME(dnr)
            fail("NameTooLongException not thrown")
        } catch (e: NameTooLongException) {
        }
    }

    @Throws(NameTooLongException::class, TextParseException::class)
    fun test_fromDNAME_disjoint() {
        val own = Name("the.owner.", null)
        val alias = Name("the.alias.", null)
        val dnr = DNAMERecord(own, DnsClass.IN, 0xABCD, alias)
        val sub = Name("sub.the.other", null)
        assertNull(sub.fromDNAME(dnr))
    }

    @Throws(TextParseException::class)
    fun test_subdomain_abs() {
        val dom = Name("the.domain.", null)
        val sub = Name("sub.of.the.domain.", null)
        assertTrue(sub.subdomain(dom))
        assertFalse(dom.subdomain(sub))
    }

    @Throws(TextParseException::class)
    fun test_subdomain_rel() {
        val dom = Name("the.domain", null)
        val sub = Name("sub.of.the.domain", null)
        assertTrue(sub.subdomain(dom))
        assertFalse(dom.subdomain(sub))
    }

    @Throws(TextParseException::class)
    fun test_subdomain_equal() {
        val dom = Name("the.domain", null)
        val sub = Name("the.domain", null)
        assertTrue(sub.subdomain(dom))
        assertTrue(dom.subdomain(sub))
    }

    @Throws(TextParseException::class)
    fun test_toString_abs() {
        val `in` = "This.Is.My.Absolute.Name."
        val n = Name(`in`, null)
        assertEquals(`in`, n.toString())
    }

    @Throws(TextParseException::class)
    fun test_toString_rel() {
        val `in` = "This.Is.My.Relative.Name"
        val n = Name(`in`, null)
        assertEquals(`in`, n.toString())
    }

    @Throws(TextParseException::class)
    fun test_toString_at() {
        val n = Name("@", null)
        assertEquals("@", n.toString())
    }

    @Throws(TextParseException::class)
    fun test_toString_root() {
        assertEquals(".", root.toString())
    }

    @Throws(TextParseException::class)
    fun test_toString_wild() {
        val `in` = "*.A.b.c.e"
        val n = Name(`in`, null)
        assertEquals(`in`, n.toString())
    }

    @Throws(TextParseException::class)
    fun test_toString_escaped() {
        val `in` = "my.escaped.junk\\128.label."
        val n = Name(`in`, null)
        assertEquals(`in`, n.toString())
    }

    @Throws(TextParseException::class, WireParseException::class)
    fun test_toString_special_char() {
        val raw = byteArrayOf(
            1,
            '"'.code.toByte(),
            1,
            '('.code.toByte(),
            1,
            ')'.code.toByte(),
            1,
            '.'.code.toByte(),
            1,
            ';'.code.toByte(),
            1,
            '\\'.code.toByte(),
            1,
            '@'.code.toByte(),
            1,
            '$'.code.toByte(),
            0
        )
        val exp = "\\\".\\(.\\).\\..\\;.\\\\.\\@.\\$."
        val n = Name(DnsInput(raw))
        assertEquals(exp, n.toString())
    }

    class Test_toWire : TestCase() {
        @Throws(TextParseException::class)
        fun test_rel() {
            val n = Name("A.Relative.Name", null)
            try {
                n.toWire(DnsOutput(), null)
                fail("IllegalArgumentException not thrown")
            } catch (ignored: IllegalArgumentException) {
            }
        }

        @Throws(TextParseException::class)
        fun test_null_Compression() {
            val raw = byteArrayOf(
                1,
                'A'.code.toByte(),
                5,
                'B'.code.toByte(),
                'a'.code.toByte(),
                's'.code.toByte(),
                'i'.code.toByte(),
                'c'.code.toByte(),
                4,
                'N'.code.toByte(),
                'a'.code.toByte(),
                'm'.code.toByte(),
                'e'.code.toByte(),
                0
            )
            val n = Name("A.Basic.Name.", null)
            val o = DnsOutput()
            n.toWire(o, null)
            assertTrue(Arrays.equals(raw, o.toByteArray()))
        }

        @Throws(TextParseException::class)
        fun test_empty_Compression() {
            val raw = byteArrayOf(
                1,
                'A'.code.toByte(),
                5,
                'B'.code.toByte(),
                'a'.code.toByte(),
                's'.code.toByte(),
                'i'.code.toByte(),
                'c'.code.toByte(),
                4,
                'N'.code.toByte(),
                'a'.code.toByte(),
                'm'.code.toByte(),
                'e'.code.toByte(),
                0
            )
            val n = Name("A.Basic.Name.", null)
            val c = Compression()
            val o = DnsOutput()
            n.toWire(o, c)
            assertTrue(Arrays.equals(raw, o.toByteArray()))
            assertEquals(0, c[n])
        }

        @Throws(TextParseException::class)
        fun test_with_exact_Compression() {
            val n = Name("A.Basic.Name.", null)
            val c = Compression()
            c.add(256, n)
            val exp = byteArrayOf(0xC1.toByte(), 0x0)
            val o = DnsOutput()
            n.toWire(o, c)
            assertTrue(Arrays.equals(exp, o.toByteArray()))
            assertEquals(256, c[n])
        }

        @Throws(TextParseException::class)
        fun test_with_partial_Compression() {
            val d = Name("Basic.Name.", null)
            val n = Name("A.Basic.Name.", null)
            val c = Compression()
            c.add(257, d)
            val exp = byteArrayOf(1, 'A'.code.toByte(), 0xC1.toByte(), 0x1)
            val o = DnsOutput()
            n.toWire(o, c)
            assertTrue(Arrays.equals(exp, o.toByteArray()))
            assertEquals(257, c[d])
            assertEquals(0, c[n])
        }

        @Throws(TextParseException::class)
        fun test_0arg_rel() {
            val n = Name("A.Relative.Name", null)
            try {
                n.toWire()
                fail("IllegalArgumentException not thrown")
            } catch (ignored: IllegalArgumentException) {
            }
        }

        @Throws(TextParseException::class)
        fun test_0arg() {
            val raw = byteArrayOf(
                1,
                'A'.code.toByte(),
                5,
                'B'.code.toByte(),
                'a'.code.toByte(),
                's'.code.toByte(),
                'i'.code.toByte(),
                'c'.code.toByte(),
                4,
                'N'.code.toByte(),
                'a'.code.toByte(),
                'm'.code.toByte(),
                'e'.code.toByte(),
                0
            )
            val n = Name("A.Basic.Name.", null)
            val out = n.toWire()
            assertTrue(Arrays.equals(raw, out))
        }

        fun test_root() {
            val out = root.toWire()
            assertTrue(Arrays.equals(byteArrayOf(0), out))
        }

        @Throws(TextParseException::class)
        fun test_3arg() {
            val d = Name("Basic.Name.", null)
            val n = Name("A.Basic.Name.", null)
            val c = Compression()
            c.add(257, d)
            val exp = byteArrayOf(1, 'A'.code.toByte(), 0xC1.toByte(), 0x1)
            val o = DnsOutput()
            n.toWire(o, c, false)
            assertTrue(Arrays.equals(exp, o.toByteArray()))
            assertEquals(257, c[d])
            assertEquals(0, c[n])
        }
    }

    class Test_toWireCanonical : TestCase() {
        @Throws(TextParseException::class)
        fun test_basic() {
            val raw = byteArrayOf(
                1,
                'a'.code.toByte(),
                5,
                'b'.code.toByte(),
                'a'.code.toByte(),
                's'.code.toByte(),
                'i'.code.toByte(),
                'c'.code.toByte(),
                4,
                'n'.code.toByte(),
                'a'.code.toByte(),
                'm'.code.toByte(),
                'e'.code.toByte(),
                0
            )

            val n = Name("A.Basic.Name.", null)
            val o = DnsOutput()
            n.toWireCanonical(o)
            assertTrue(Arrays.equals(raw, o.toByteArray()))
        }

        @Throws(TextParseException::class)
        fun test_0arg() {
            val raw = byteArrayOf(
                1,
                'a'.code.toByte(),
                5,
                'b'.code.toByte(),
                'a'.code.toByte(),
                's'.code.toByte(),
                'i'.code.toByte(),
                'c'.code.toByte(),
                4,
                'n'.code.toByte(),
                'a'.code.toByte(),
                'm'.code.toByte(),
                'e'.code.toByte(),
                0
            )

            val n = Name("A.Basic.Name.", null)
            val out = n.toWireCanonical()
            assertTrue(Arrays.equals(raw, out))
        }

        fun test_root() {
            val out = root.toWireCanonical()
            assertTrue(Arrays.equals(byteArrayOf(0), out))
        }

        @Throws(TextParseException::class)
        fun test_empty() {
            val n = Name("@", null)
            val out = n.toWireCanonical()
            assertTrue(Arrays.equals(ByteArray(0), out))
        }

        @Throws(TextParseException::class)
        fun test_3arg() {
            val d = Name("Basic.Name.", null)
            val n = Name("A.Basic.Name.", null)
            val c = Compression()
            c.add(257, d)
            val exp = byteArrayOf(
                1,
                'a'.code.toByte(),
                5,
                'b'.code.toByte(),
                'a'.code.toByte(),
                's'.code.toByte(),
                'i'.code.toByte(),
                'c'.code.toByte(),
                4,
                'n'.code.toByte(),
                'a'.code.toByte(),
                'm'.code.toByte(),
                'e'.code.toByte(),
                0
            )
            val o = DnsOutput()
            n.toWire(o, c, true)
            assertTrue(Arrays.equals(exp, o.toByteArray()))
            assertEquals(257, c[d])
            assertEquals(-1, c[n])
        }
    }

    class Test_equals : TestCase() {
        @Throws(TextParseException::class)
        fun test_same() {
            val n = Name("A.Name.", null)
            assertTrue(n.equals(n))
        }

        @Throws(TextParseException::class)
        fun test_null() {
            val n = Name("A.Name.", null)
            assertFalse(n.equals(null))
        }

        @Throws(TextParseException::class)
        fun test_notName() {
            val n = Name("A.Name.", null)
            assertFalse(n.equals(Any()))
        }

        @Throws(TextParseException::class)
        fun test_abs() {
            val n = Name("A.Name.", null)
            val n2 = Name("a.name.", null)
            assertTrue(n.equals(n2))
            assertTrue(n2.equals(n))
        }

        @Throws(TextParseException::class)
        fun test_rel() {
            val n1 = Name("A.Relative.Name", null)
            val n2 = Name("a.relative.name", null)
            assertTrue(n1.equals(n2))
            assertTrue(n2.equals(n1))
        }

        @Throws(TextParseException::class)
        fun test_mixed() {
            val n1 = Name("A.Name", null)
            val n2 = Name("a.name.", null)
            assertFalse(n1.equals(n2))
            assertFalse(n2.equals(n1))
        }

        @Throws(TextParseException::class)
        fun test_weird() {
            val n1 = Name("ab.c", null)
            val n2 = Name("abc.", null)
            assertFalse(n1.equals(n2))
            assertFalse(n2.equals(n1))
        }
    }

    class Test_compareTo : TestCase() {
        @Throws(TextParseException::class)
        fun test_same() {
            val n = Name("A.Name", null)
            assertEquals(0, n.compareTo(n))
        }

        @Throws(TextParseException::class)
        fun test_equal() {
            val n1 = Name("A.Name.", null)
            val n2 = Name("a.name.", null)
            assertEquals(0, n1.compareTo(n2))
            assertEquals(0, n2.compareTo(n1))
        }

        @Throws(TextParseException::class)
        fun test_close() {
            val n1 = Name("a.name", null)
            val n2 = Name("a.name.", null)
            assertTrue(n1.compareTo(n2) > 0)
            assertTrue(n2.compareTo(n1) < 0)
        }

        @Throws(TextParseException::class)
        fun test_disjoint() {
            val n1 = Name("b", null)
            val n2 = Name("c", null)
            assertTrue(n1.compareTo(n2) < 0)
            assertTrue(n2.compareTo(n1) > 0)
        }

        @Throws(TextParseException::class)
        fun test_label_prefix() {
            val n1 = Name("thisIs.a.", null)
            val n2 = Name("thisIsGreater.a.", null)
            assertTrue(n1.compareTo(n2) < 0)
            assertTrue(n2.compareTo(n1) > 0)
        }

        @Throws(TextParseException::class)
        fun test_more_labels() {
            val n1 = Name("c.b.a.", null)
            val n2 = Name("d.c.b.a.", null)
            assertTrue(n1.compareTo(n2) < 0)
            assertTrue(n2.compareTo(n1) > 0)
        }
    }

    @Throws(TextParseException::class)
    fun test_canonicalize() {
        val n1 = Name("ABC.com", null)
        val n2 = Name("abc.com", null)
        val n3 = Name("\\193.com", null)
        val cn1 = n1.canonicalize()
        val cn2 = n2.canonicalize()
        val cn3 = n3.canonicalize()
        assertNotSame(n1, cn1)
        assertEquals(n1, cn1)
        assertSame(n2, cn2)
        assertSame(n3, cn3)
        assertEquals(cn1.toString(), cn2.toString())
        assertFalse(
            n1.toString() == n2.toString()
        )
        assertEquals(cn1.toString(), cn2.toString())
    }

    @Throws(TextParseException::class)
    fun test_to_string() {
        val n1 = Name("abc.com")
        val n2 = Name("abc.com.")
        assertEquals(n1.toString(true), n1.toString(true))
        assertFalse(n2.toString(true) == n2.toString(false))
        assertEquals(n2.toString(true) + ".", n2.toString(false))
        assertEquals(root.toString(true), root.toString(false))
        assertEquals(empty.toString(true), empty.toString(false))
    }

    @Throws(TextParseException::class)
    fun test_absolute() {
        val n1 = Name("abc.com", null)
        val n2 = Name("abc.com.", null)
        val n3 = Name("abc.com", root)
        val n4 = Name("abc.com", n1)
        val n5 = Name("abc.com\\000", null)
        assertFalse(n1.isAbsolute)
        assertTrue(n2.isAbsolute)
        assertTrue(n3.isAbsolute)
        assertFalse(n4.isAbsolute)
        assertFalse(n5.isAbsolute)
    }

    companion object {
        fun suite(): Test {
            val s = TestSuite()
            s.addTestSuite(Test_String_init::class.java)
            s.addTestSuite(Test_DNSInput_init::class.java)
            s.addTestSuite(NameTest::class.java)
            s.addTestSuite(Test_toWire::class.java)
            s.addTestSuite(Test_toWireCanonical::class.java)
            s.addTestSuite(Test_equals::class.java)
            s.addTestSuite(Test_compareTo::class.java)
            return s
        }
    }
}
