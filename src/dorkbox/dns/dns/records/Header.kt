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

import dorkbox.dns.dns.DnsInput
import dorkbox.dns.dns.DnsOutput
import dorkbox.dns.dns.constants.DnsOpCode
import dorkbox.dns.dns.constants.DnsResponseCode
import dorkbox.dns.dns.constants.DnsSection
import dorkbox.dns.dns.constants.Flags
import dorkbox.os.OS.LINE_SEPARATOR
import dorkbox.util.FastThreadLocal
import dorkbox.util.MersenneTwisterFast

/**
 * A DNS message header
 *
 * @author Brian Wellington
 * @see DnsMessage
 */
class Header : Cloneable {
    internal var id = 0

    var flagsByte = 0
        private set

    private var counts = IntArray(4)

    /**
     * Create a new empty header with a random message id
     */
    constructor() {
        init()
    }

    private fun init() {
        counts = IntArray(4)
        flagsByte = 0
        id = -1
    }

    /**
     * Creates a new Header from its DNS wire format representation
     *
     * @param b A byte array containing the DNS Header.
     */
    constructor(b: ByteArray?) : this(DnsInput(b!!)) {}

    /**
     * Parses a Header from a stream containing DNS wire format.
     */
    internal constructor(`in`: DnsInput) : this(`in`.readU16()) {
        flagsByte = `in`.readU16()
        for (i in counts.indices) {
            counts[i] = `in`.readU16()
        }
    }

    /**
     * Create a new empty header.
     *
     * @param id The message id
     */
    constructor(id: Int) {
        init()
        iD = id
    }

    fun toWire(): ByteArray {
        val out = DnsOutput()
        toWire(out)
        return out.toByteArray()
    }

    fun toWire(out: DnsOutput) {
        out.writeU16(iD)
        out.writeU16(flagsByte)
        for (i in counts.indices) {
            out.writeU16(counts[i])
        }
    }
    /**
     * Retrieves the message ID
     */
    /**
     * Sets the message ID
     */
    var iD: Int
        get() {
            if (id >= 0) {
                return id
            }
            synchronized(this) {
                if (id < 0) {
                    id = random.get().nextInt(0xffff)
                }
                return id
            }
        }
        set(id) {
            require(!(id < 0 || id > 0xffff)) { "DNS message ID $id is out of range" }
            this.id = id
        }

    /**
     * Sets a flag to the supplied value
     *
     * @see Flags
     */
    fun setFlag(flag: Flags) {
        checkFlag(flag)
        flagsByte = setFlag(flagsByte, flag, true)
    }

    /**
     * Sets a flag to the supplied value
     *
     * @see Flags
     */
    fun unsetFlag(flag: Flags) {
        checkFlag(flag)
        flagsByte = setFlag(flagsByte, flag, false)
    }

    fun getFlags(): BooleanArray {
        val array = BooleanArray(16)
        for (i in array.indices) {
            if (Flags.isFlag(i)) {
                array[i] = getFlag(i)
            }
        }
        return array
    }

    /**
     * Retrieves a flag
     *
     * @see Flags
     */
    fun getFlag(flag: Flags): Boolean {
        // bit s are indexed from left to right
        return flagsByte and (1 shl 15) - flag.value() != 0
    }

    /**
     * Retrieves a flag.
     *
     * @param flagValue ALWAYS checked before using, so additional checks are not necessary
     * @see Flags
     */
    private fun getFlag(flagValue: Int): Boolean {
        // bits are indexed from left to right
        return flagsByte and (1 shl 15) - flagValue != 0
    }

    fun setCount(field: Int, value: Int) {
        require(!(value < 0 || value > 0xFFFF)) { "DNS section count $value is out of range" }
        counts[field] = value
    }

    fun incCount(field: Int) {
        check(counts[field] != 0xFFFF) { "DNS section count cannot " + "be incremented" }
        counts[field]++
    }

    fun decCount(field: Int) {
        check(counts[field] != 0) { "DNS section count cannot " + "be decremented" }
        counts[field]--
    }

    /* Creates a new Header identical to the current one */
    public override fun clone(): Any {
        val h = Header()
        h.id = id
        h.flagsByte = flagsByte
        System.arraycopy(counts, 0, h.counts, 0, counts.size)
        return h
    }

    /**
     * Converts the header into a String
     */
    override fun toString(): String {
        return toStringWithRcode(rcode)
    }
    /**
     * Retrieves the message's rcode
     *
     * @see DnsResponseCode
     */
    /**
     * Sets the message's rcode
     *
     * @see DnsResponseCode
     */
    var rcode: Int
        get() = flagsByte and 0xF
        set(value) {
            require(!(value < 0 || value > 0xF)) { "DNS DnsResponseCode $value is out of range" }
            flagsByte = flagsByte and 0xF.inv()
            flagsByte = flagsByte or value
        }

    fun toStringWithRcode(newrcode: Int): String {
        val sb = StringBuilder()
        sb.append(";; ->>HEADER<<- ")
        sb.append("opcode: " + DnsOpCode.string(opcode))
        sb.append(", status: " + DnsResponseCode.string(newrcode))
        sb.append(", id: " + iD)
        sb.append(LINE_SEPARATOR)
        sb.append(";; flags: ").append(printFlags())
        sb.append("; ")
        for (i in 0..3) {
            sb.append(DnsSection.string(i)).append(": ").append(getCount(i)).append(" ")
        }
        return sb.toString()
    }
    /**
     * Retrieves the mesasge's opcode
     *
     * @see DnsOpCode
     */
    /**
     * Sets the message's opcode
     *
     * @see DnsOpCode
     */
    var opcode: Int
        get() = flagsByte shr 11 and 0xF
        set(value) {
            require(!(value < 0 || value > 0xF)) { "DNS DnsOpCode " + value + "is out of range" }
            flagsByte = flagsByte and 0x87FF
            flagsByte = flagsByte or (value shl 11)
        }

    /**
     * Retrieves the record count for the given section
     *
     * @see DnsSection
     */
    fun getCount(field: Int): Int {
        return counts[field]
    }

    /**
     * Converts the header's flags into a String
     */
    fun printFlags(): String {
        val sb = StringBuilder()
        for (i in 0..15) {
            if (Flags.isFlag(i) && getFlag(i)) {
                val flag = Flags.Companion.toFlag(i)
                sb.append(flag.string())
                sb.append(" ")
            }
        }
        return sb.toString()
    }

    companion object {
        private val random: FastThreadLocal<MersenneTwisterFast> = object : FastThreadLocal<MersenneTwisterFast>() {
            override fun initialValue(): MersenneTwisterFast {
                return MersenneTwisterFast()
            }
        }

        /**
         * The length of a DNS Header in wire format.
         */
        const val LENGTH = 12
        private fun checkFlag(flag: Int) {
            require(Flags.isFlag(flag)) { "invalid flag bit $flag" }
        }

        private fun checkFlag(flag: Flags) {
            require(validFlag(flag)) { "invalid flag bit $flag" }
        }

        private fun validFlag(flag: Flags?): Boolean {
            return flag != null && flag.value() >= 0 && flag.value() <= 0xF && Flags.isFlag(
                flag.value().toInt()
            )
        }

        fun setFlag(flags: Int, flag: Flags, value: Boolean): Int {
            var flags = flags
            checkFlag(flag)

            // bits are indexed from left to right
            return if (value) {
                (1 shl 15 - flag.value()).let { flags = flags or it; flags }
            } else {
                (1 shl 15 - flag.value()).inv().let { flags = flags and it; flags }
            }
        }
    }
}
