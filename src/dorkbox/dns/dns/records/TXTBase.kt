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
package dorkbox.dns.dns.records

import dorkbox.dns.dns.Compression
import dorkbox.dns.dns.DnsInput
import dorkbox.dns.dns.DnsOutput
import dorkbox.dns.dns.Name
import dorkbox.dns.dns.exceptions.TextParseException
import dorkbox.dns.dns.utils.Tokenizer
import java.io.IOException

/**
 * Implements common functionality for the many record types whose format is a list of strings.
 *
 * @author Brian Wellington
 */
abstract class TXTBase : DnsRecord {
    private var strings = mutableListOf<ByteArray>()

    protected constructor() {}
    protected constructor(name: Name, type: Int, dclass: Int, ttl: Long) : super(name, type, dclass, ttl)
    protected constructor(name: Name, type: Int, dclass: Int, ttl: Long, string: String) : this(
        name,
        type,
        dclass,
        ttl,
        listOf<String>(string)
    )

    protected constructor(name: Name, type: Int, dclass: Int, ttl: Long, strings: List<String>) : super(
        name, type, dclass, ttl
    ) {
        this.strings = ArrayList(strings.size)

        val it = strings.iterator()
        try {
            while (it.hasNext()) {
                val s = it.next()
                this.strings.add(byteArrayFromString(s))
            }
        } catch (e: TextParseException) {
            throw IllegalArgumentException(e.message)
        }
    }

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        strings = ArrayList(2)
        while (`in`.remaining() > 0) {
            val b = `in`.readCountedString()
            strings.add(b)
        }
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        for (b in strings) {
            out.writeCountedString(b)
        }
    }

    /**
     * converts to a String
     */
    override fun rrToString(sb: StringBuilder) {
        val it: Iterator<ByteArray> = strings.iterator()
        while (it.hasNext()) {
            val array = it.next()
            sb.append(byteArrayToString(array, true))
            if (it.hasNext()) {
                sb.append(" ")
            }
        }
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        strings = ArrayList(2)
        while (true) {
            val t = st.get()
            if (!t.isString) {
                break
            }
            try {
                strings.add(byteArrayFromString(t.value!!))
            } catch (e: TextParseException) {
                throw st.exception(e.message ?: "")
            }
        }
        st.unget()
    }

    /**
     * Returns the text strings
     *
     * @return A list of Strings corresponding to the text strings.
     */
    fun getStrings(): List<String> {
        val list: MutableList<String> = ArrayList(strings.size)
        for (i in strings.indices) {
            list.add(byteArrayToString(strings[i], false))
        }
        return list
    }

    /**
     * Returns the text strings
     *
     * @return A list of byte arrays corresponding to the text strings.
     */
    val stringsAsByteArrays: List<ByteArray>
        get() = strings

    companion object {
        private const val serialVersionUID = -4319510507246305931L
    }
}
