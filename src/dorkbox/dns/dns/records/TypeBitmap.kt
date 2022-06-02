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

import dorkbox.collections.IntMap
import dorkbox.dns.dns.DnsInput
import dorkbox.dns.dns.DnsOutput
import dorkbox.dns.dns.constants.DnsRecordType.check
import dorkbox.dns.dns.constants.DnsRecordType.string
import dorkbox.dns.dns.constants.DnsRecordType.value
import dorkbox.dns.dns.exceptions.WireParseException
import dorkbox.dns.dns.utils.Tokenizer
import java.io.Serializable
import java.util.*

/**
 * Routines for deal with the lists of types found in NSEC/NSEC3 records.
 *
 * @author Brian Wellington
 */
internal class TypeBitmap private constructor() : Serializable {
    private val types: IntMap<Boolean>

    constructor(array: IntArray) : this() {
        for (i in array.indices) {
            check(array[i])
            types.put(array[i], java.lang.Boolean.TRUE)
        }
    }

    init {
        types = IntMap()
    }

    constructor(`in`: DnsInput) : this() {
        val lastbase = -1
        while (`in`.remaining() > 0) {
            if (`in`.remaining() < 2) {
                throw WireParseException("invalid bitmap descriptor")
            }
            val mapbase = `in`.readU8()
            if (mapbase < lastbase) {
                throw WireParseException("invalid ordering")
            }
            val maplength = `in`.readU8()
            if (maplength > `in`.remaining()) {
                throw WireParseException("invalid bitmap")
            }
            for (i in 0 until maplength) {
                val current = `in`.readU8()
                if (current == 0) {
                    continue
                }
                for (j in 0..7) {
                    if (current and (1 shl 7) - j == 0) {
                        continue
                    }
                    val typecode = mapbase * 256 + +i * 8 + j
                    types.put(typecode, java.lang.Boolean.TRUE)
                }
            }
        }
    }

    constructor(st: Tokenizer) : this() {
        while (true) {
            val t = st.get()
            if (!t.isString) {
                break
            }
            val typecode = value(t.value!!)
            if (typecode < 0) {
                throw st.exception("Invalid type: " + t.value)
            }
            types.put(typecode, java.lang.Boolean.TRUE)
        }
        st.unget()
    }

    fun toArray(): IntArray {
        val array = IntArray(types.size)
        var n = 0
        val keys = types.keys()
        while (keys.hasNext) {
            array[n++] = keys.next()
        }
        return array
    }

    override fun toString(): String {
        val sb = StringBuilder()
        val keys = types.keys()
        while (keys.hasNext) {
            val t = keys.next()
            sb.append(string(t)).append(' ')
        }

        // remove the last ' '
        val length = sb.length
        if (length > 1) {
            sb.delete(length - 1, length)
        }
        return sb.toString()
    }

    fun toWire(out: DnsOutput) {
        if (types.size == 0) {
            return
        }
        var mapbase = -1
        val map = TreeSet<Int>()
        val keys = types.keys()
        while (keys.hasNext) {
            val t = keys.next()
            val base = t shr 8
            if (base != mapbase) {
                if (map.size > 0) {
                    mapToWire(out, map, mapbase)
                    map.clear()
                }
                mapbase = base
            }
            map.add(t)
        }
        mapToWire(out, map, mapbase)
    }

    fun empty(): Boolean {
        return types.size == 0
    }

    operator fun contains(typecode: Int): Boolean {
        return types.containsKey(typecode)
    }

    companion object {
        private const val serialVersionUID = -125354057735389003L

        /**
         * @param map this must be an ordered data structure!
         */
        private fun mapToWire(out: DnsOutput, map: TreeSet<Int>, mapbase: Int) {
            val arraymax = map.last() and 0xFF
            val arraylength = arraymax / 8 + 1
            val array = IntArray(arraylength)
            out.writeU8(mapbase)
            out.writeU8(arraylength)
            val it: Iterator<Int> = map.iterator()
            while (it.hasNext()) {
                val typecode = it.next()
                array[(typecode and 0xFF) / 8] = array[(typecode and 0xFF) / 8] or (1 shl 7) - typecode % 8
            }
            for (j in 0 until arraylength) {
                out.writeU8(array[j])
            }
        }
    }
}
