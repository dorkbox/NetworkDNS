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
 * Routines for converting between Strings of hex-encoded data and arrays of
 * binary data.  This is not actually used by DNS.
 *
 * @author Brian Wellington
 */
object base16 {
    private const val Base16 = "0123456789ABCDEF"

    /**
     * Convert binary data to a hex-encoded String
     *
     * @param b An array containing binary data
     *
     * @return A String containing the encoded data
     */
    @JvmStatic
    fun toString(b: ByteArray): String {
        val os = ByteArrayOutputStream()
        for (i in b.indices) {
            val value = (b[i].toInt() and 0xFF).toShort()
            val high = (value.toInt() shr 4).toByte()
            val low = (value.toInt() and 0xF).toByte()

            os.write(Base16[high.toInt()].code)
            os.write(Base16[low.toInt()].code)
        }

        return String(os.toByteArray())
    }

    /**
     * Convert a hex-encoded String to binary data
     *
     * @param str A String containing the encoded data
     *
     * @return An array containing the binary data, or null if the string is invalid
     */
    fun fromString(str: String): ByteArray? {
        val bs = ByteArrayOutputStream()
        val raw = str.toByteArray()
        for (i in raw.indices) {
            if (!Character.isWhitespace(Char(raw[i].toUShort()))) {
                bs.write(raw[i].toInt())
            }
        }

        val `in` = bs.toByteArray()
        if (`in`.size % 2 != 0) {
            return null
        }
        bs.reset()


        val ds = DataOutputStream(bs)
        var i = 0

        while (i < `in`.size) {
            val high = Base16.indexOf(Char(`in`[i].toUShort()).uppercaseChar()).toByte()
            val low = Base16.indexOf(Char(`in`[i + 1].toUShort()).uppercaseChar()).toByte()

            try {
                ds.writeByte((high.toInt() shl 4) + low)
            } catch (ignored: IOException) {
            }

            i += 2
        }
        return bs.toByteArray()
    }
}
