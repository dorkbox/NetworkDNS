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
import dorkbox.dns.dns.Mnemonic
import dorkbox.dns.dns.exceptions.WireParseException
import java.io.IOException
import java.util.*

/**
 * DNS extension options, as described in RFC 2671.  The rdata of an OPT record
 * is defined as a list of options; this represents a single option.
 *
 * @author Brian Wellington
 * @author Ming Zhou &lt;mizhou@bnivideo.com&gt;, Beaumaris Networks
 */
abstract class EDNSOption(code: Int) {
    /**
     * Returns the EDNS Option's code.
     *
     * @return the option code
     */
    val code: Int

    object Code {
        /**
         * Name Server Identifier, RFC 5001
         */
        const val NSID = 3

        /**
         * Client Subnet, defined in draft-vandergaast-edns-client-subnet-02
         */
        const val CLIENT_SUBNET = 8
        private val codes = Mnemonic("EDNS Option Codes", Mnemonic.CASE_UPPER)

        init {
            codes.setMaximum(0xFFFF)
            codes.setPrefix("CODE")
            codes.setNumericAllowed(true)
            codes.add(NSID, "NSID")
            codes.add(CLIENT_SUBNET, "CLIENT_SUBNET")
        }

        /**
         * Converts an EDNS Option Code into its textual representation
         */
        fun string(code: Int): String {
            return codes.getText(code)
        }

        /**
         * Converts a textual representation of an EDNS Option Code into its
         * numeric value.
         *
         * @param s The textual representation of the option code
         *
         * @return The option code, or -1 on error.
         */
        fun value(s: String?): Int {
            return codes.getValue(s!!)
        }
    }

    /**
     * Creates an option with the given option code and data.
     */
    init {
        this.code = DnsRecord.checkU16("code", code)
    }

    /**
     * Converts the wire format of an EDNS Option (the option data only) into the
     * type-specific format.
     *
     * @param in The input Stream.
     */
    @Throws(IOException::class)
    abstract fun optionFromWire(`in`: DnsInput)

    /**
     * Converts an EDNS Option (including code and length) into wire format.
     *
     * @return The option, in wire format.
     */
    @Throws(IOException::class)
    fun toWire(): ByteArray {
        val out = DnsOutput()
        toWire(out)
        return out.toByteArray()
    }

    /**
     * Converts an EDNS Option (including code and length) into wire format.
     *
     * @param out The output stream.
     */
    fun toWire(out: DnsOutput) {
        out.writeU16(code)
        val lengthPosition = out.current()
        out.writeU16(0) /* until we know better */
        optionToWire(out)
        val length = out.current() - lengthPosition - 2
        out.writeU16At(length, lengthPosition)
    }

    /**
     * Converts an EDNS Option (the type-specific option data only) into wire format.
     *
     * @param out The output stream.
     */
    abstract fun optionToWire(out: DnsOutput)

    /**
     * Generates a hash code based on the EDNS Option's data.
     */
    override fun hashCode(): Int {
        val array = data
        var hashval = 0
        for (i in array.indices) {
            hashval += (hashval shl 3) + (array[i].toInt() and 0xFF)
        }
        return hashval
    }

    /**
     * Determines if two EDNS Options are identical.
     *
     * @param arg The option to compare to
     *
     * @return true if the options are equal, false otherwise.
     */
    override fun equals(arg: Any?): Boolean {
        if (arg == null || arg !is EDNSOption) {
            return false
        }
        val opt = arg
        return if (code != opt.code) {
            false
        } else Arrays.equals(data, opt.data)
    }

    override fun toString(): String {
        val sb = StringBuilder()
        sb.append("{")
        sb.append(Code.string(code))
        sb.append(": ")
        sb.append(optionToString())
        sb.append("}")
        return sb.toString()
    }

    abstract fun optionToString(): String?

    /**
     * Returns the EDNS Option's data, as a byte array.
     *
     * @return the option data
     */
    open val data: ByteArray
        get() {
            val out = DnsOutput()
            optionToWire(out)
            return out.toByteArray()
        }

    companion object {
        /**
         * Converts the wire format of an EDNS Option (including code and length) into
         * the type-specific format.
         *
         * @return The option, in wire format.
         */
        @Throws(IOException::class)
        fun fromWire(b: ByteArray?): EDNSOption {
            return fromWire(DnsInput(b!!))
        }

        /**
         * Converts the wire format of an EDNS Option (including code and length) into
         * the type-specific format.
         *
         * @param in The input stream.
         */
        @JvmStatic
        @Throws(IOException::class)
        fun fromWire(`in`: DnsInput): EDNSOption {
            val code: Int
            val length: Int
            code = `in`.readU16()
            length = `in`.readU16()
            if (`in`.remaining() < length) {
                throw WireParseException("truncated option")
            }
            `in`.setActive(length)
            val option: EDNSOption
            option = when (code) {
                Code.NSID -> NSIDOption()
                Code.CLIENT_SUBNET -> ClientSubnetOption()
                else -> GenericEDNSOption(code)
            }
            option.optionFromWire(`in`)
            `in`.restoreActive()
            return option
        }
    }
}
