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

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.IOException

/**
 * Routines for converting between Strings of base32-encoded data and arrays
 * of binary data.  This currently supports the base32 and base32hex alphabets
 * specified in RFC 4648, sections 6 and 7.
 *
 * @author Brian Wellington
 */
class base32
/**
 * Creates an object that can be used to do base32 conversions.
 *
 * @param alphabet Which alphabet should be used
 * @param padding Whether padding should be used
 * @param lowercase Whether lowercase characters should be used.
 * default parameters (The standard base32 alphabet, no padding, uppercase)
 */(private val alphabet: String, private val padding: Boolean, private val lowercase: Boolean) {
    object Alphabet {
        const val BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567="
        const val BASE32HEX = "0123456789ABCDEFGHIJKLMNOPQRSTUV="
    }

    /**
     * Convert binary data to a base32-encoded String
     *
     * @param b An array containing binary data
     *
     * @return A String containing the encoded data
     */
    fun toString(b: ByteArray): String {
        val os = ByteArrayOutputStream()

        for (i in (0 until (b.size + 4) / 5)) {
            val s = ShortArray(5)
            val t = IntArray(8)
            var blocklen = 5
            for (j in 0..4) {
                if (i * 5 + j < b.size) {
                    s[j] = (b[i * 5 + j].toInt() and 0xFF).toShort()
                } else {
                    s[j] = 0
                    blocklen--
                }
            }
            val padlen = blockLenToPadding(blocklen)

            // convert the 5 byte block into 8 characters (values 0-31).

            // upper 5 bits from first byte
            t[0] = (s[0].toInt() shr 3 and 0x1F).toByte().toInt()
            // lower 3 bits from 1st byte, upper 2 bits from 2nd.
            t[1] = (s[0].toInt() and 0x07 shl 2 or (s[1].toInt() shr 6 and 0x03)).toByte().toInt()
            // bits 5-1 from 2nd.
            t[2] = (s[1].toInt() shr 1 and 0x1F).toByte().toInt()
            // lower 1 bit from 2nd, upper 4 from 3rd
            t[3] = (s[1].toInt() and 0x01 shl 4 or (s[2].toInt() shr 4 and 0x0F)).toByte().toInt()
            // lower 4 from 3rd, upper 1 from 4th.
            t[4] = (s[2].toInt() and 0x0F shl 1 or (s[3].toInt() shr 7 and 0x01)).toByte().toInt()
            // bits 6-2 from 4th
            t[5] = (s[3].toInt() shr 2 and 0x1F).toByte().toInt()
            // lower 2 from 4th, upper 3 from 5th;
            t[6] = (s[3].toInt() and 0x03 shl 3 or (s[4].toInt() shr 5 and 0x07)).toByte().toInt()
            // lower 5 from 5th;
            t[7] = (s[4].toInt() and 0x1F).toByte().toInt()

            // write out the actual characters.
            for (j in 0 until t.size - padlen) {
                var c = alphabet[t[j]]
                if (lowercase) {
                    c = c.lowercaseChar()
                }
                os.write(c.code)
            }

            // write out the padding (if any)
            if (padding) {
                for (j in t.size - padlen until t.size) {
                    os.write('='.code)
                }
            }
        }
        return String(os.toByteArray())
    }

    /**
     * Convert a base32-encoded String to binary data
     *
     * @param str A String containing the encoded data
     *
     * @return An array containing the binary data, or null if the string is invalid
     */
    fun fromString(str: String): ByteArray? {
        val bs = ByteArrayOutputStream()
        val raw = str.toByteArray()
        for (i in raw.indices) {
            var c = Char(raw[i].toUShort())
            if (!Character.isWhitespace(c)) {
                c = c.uppercaseChar()
                bs.write(c.code.toByte().toInt())
            }
        }
        if (padding) {
            if (bs.size() % 8 != 0) {
                return null
            }
        } else {
            while (bs.size() % 8 != 0) {
                bs.write('='.code)
            }
        }
        val `in` = bs.toByteArray()
        bs.reset()
        val ds = DataOutputStream(bs)
        for (i in 0 until `in`.size / 8) {
            val s = ShortArray(8)
            val t = IntArray(5)
            var padlen = 8
            for (j in 0..7) {
                val c = Char(`in`[i * 8 + j].toUShort())
                if (c == '=') {
                    break
                }
                s[j] = alphabet.indexOf(Char(`in`[i * 8 + j].toUShort())).toShort()
                if (s[j] < 0) {
                    return null
                }
                padlen--
            }
            val blocklen = paddingToBlockLen(padlen)
            if (blocklen < 0) {
                return null
            }

            // all 5 bits of 1st, high 3 (of 5) of 2nd
            t[0] = s[0].toInt() shl 3 or (s[1].toInt() shr 2)
            // lower 2 of 2nd, all 5 of 3rd, high 1 of 4th
            t[1] = s[1].toInt() and 0x03 shl 6 or (s[2].toInt() shl 1) or (s[3].toInt() shr 4)
            // lower 4 of 4th, high 4 of 5th
            t[2] = s[3].toInt() and 0x0F shl 4 or (s[4].toInt() shr 1 and 0x0F)
            // lower 1 of 5th, all 5 of 6th, high 2 of 7th
            t[3] = s[4].toInt() shl 7 or (s[5].toInt() shl 2) or (s[6].toInt() shr 3)
            // lower 3 of 7th, all of 8th
            t[4] = s[6].toInt() and 0x07 shl 5 or s[7].toInt()
            try {
                for (j in 0 until blocklen) {
                    ds.writeByte((t[j] and 0xFF).toByte().toInt())
                }
            } catch (e: IOException) {
            }
        }
        return bs.toByteArray()
    }

    companion object {
        private fun blockLenToPadding(blocklen: Int): Int {
            return when (blocklen) {
                1 -> 6
                2 -> 4
                3 -> 3
                4 -> 1
                5 -> 0
                else -> -1
            }
        }

        private fun paddingToBlockLen(padlen: Int): Int {
            return when (padlen) {
                6 -> 1
                4 -> 2
                3 -> 3
                1 -> 4
                0 -> 5
                else -> -1
            }
        }
    }
}
