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
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.records.EDNSOption.Companion.fromWire
import dorkbox.dns.dns.utils.Tokenizer
import java.io.IOException
import java.util.*

/**
 * Options - describes Extended DNS (EDNS) properties of a DnsMessage.
 * No specific options are defined other than those specified in the
 * header.  An OPT should be generated by Resolver.
 *
 *
 * EDNS is a method to extend the DNS protocol while providing backwards
 * compatibility and not significantly changing the protocol.  This
 * implementation of EDNS is mostly complete at level 0.
 *
 * @author Brian Wellington
 * @see DnsMessage
 */
class OPTRecord : DnsRecord {
    private var options: MutableList<EDNSOption>? = null

    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = OPTRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        if (`in`.remaining() > 0) {
            options = ArrayList()
        }
        while (`in`.remaining() > 0) {
            val option = fromWire(`in`)
            options!!.add(option)
        }
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        if (options == null) {
            return
        }
        val it: Iterator<*> = options!!.iterator()
        while (it.hasNext()) {
            val option = it.next() as EDNSOption
            option.toWire(out)
        }
    }

    /**
     * Converts rdata to a String
     */
    override fun rrToString(sb: StringBuilder) {
        if (options != null) {
            sb.append(options)
            sb.append(" ")
        }
        sb.append(" ; payload ")
        sb.append(payloadSize)
        sb.append(", xrcode ")
        sb.append(extendedRcode)
        sb.append(", version ")
        sb.append(version)
        sb.append(", flags ")
        sb.append(flags)
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        throw st.exception("no text format defined for OPT")
    }

    /**
     * Determines if two OPTRecords are identical.  This compares the name, type,
     * class, and rdata (with names canonicalized).  Additionally, because TTLs
     * are relevant for OPT records, the TTLs are compared.
     *
     * @param arg The record to compare to
     *
     * @return true if the records are equal, false otherwise.
     */
    override fun equals(arg: Any?): Boolean {
        return super.equals(arg) && ttl === (arg as OPTRecord).ttl
    }

    /**
     * Returns the maximum allowed payload size.
     */
    val payloadSize: Int
        get() = dclass

    /**
     * Returns the extended DnsResponseCode
     *
     * @see DnsResponseCode
     */
    val extendedRcode: Int
        get() = (ttl ushr 24).toInt()

    /**
     * Returns the highest supported EDNS version
     */
    val version: Int
        get() = (ttl ushr 16 and 0xFF).toInt()

    /**
     * Returns the EDNS flags
     */
    val flags: Int
        get() = (ttl and 0xFFFF).toInt()
    /**
     * Creates an OPT Record.  This is normally called by SimpleResolver, but can
     * also be called by a server.
     *
     * @param payloadSize The size of a packet that can be reassembled on the
     * sending host.
     * @param xrcode The value of the extended rcode field.  This is the upper
     * 16 bits of the full rcode.
     * @param flags Additional message flags.
     * @param version The EDNS version that this DNS implementation supports.
     * This should be 0 for dnsjava.
     * @param options The list of options that comprise the data field.  There
     * are currently no defined options.
     *
     * @see ExtendedFlags
     */
    /**
     * Creates an OPT Record with no data.  This is normally called by
     * SimpleResolver, but can also be called by a server.
     */
    /**
     * Creates an OPT Record with no data.  This is normally called by
     * SimpleResolver, but can also be called by a server.
     *
     * @param payloadSize The size of a packet that can be reassembled on the
     * sending host.
     * @param xrcode The value of the extended rcode field.  This is the upper
     * 16 bits of the full rcode.
     * @param flags Additional message flags.
     * @param version The EDNS version that this DNS implementation supports.
     * This should be 0 for dnsjava.
     *
     * @see ExtendedFlags
     */
    constructor(payloadSize: Int, xrcode: Int, version: Int, flags: Int = 0, options: List<EDNSOption?>? = null) : super(
        Name.root,
        DnsRecordType.OPT,
        payloadSize,
        0
    ) {
        checkU16("payloadSize", payloadSize)
        checkU8("xrcode", xrcode)
        checkU8("version", version)
        checkU16("flags", flags)
        ttl = (xrcode.toLong() shl 24) + (version.toLong() shl 16) + flags

        if (options != null) {
            this.options = ArrayList(options)
        }
    }

    private val emptyList = listOf<EDNSOption>()

    /**
     * Gets all options in the OPTRecord.  This returns a list of EDNSOptions.
     */
    fun getOptions(): List<EDNSOption> {
        return if (options == null) {
            emptyList
        } else {
            Collections.unmodifiableList(options)
        }
    }

    /**
     * Gets all options in the OPTRecord with a specific code.  This returns a list
     * of EDNSOptions.
     */
    fun getOptions(code: Int): List<EDNSOption> {
        if (options == null) {
            return emptyList
        }

        val list = mutableListOf<EDNSOption>()

        val it: Iterator<EDNSOption> = options!!.iterator()
        while (it.hasNext()) {
            val opt = it.next()
            if (opt.code == code) {
                list.add(opt)
            }
        }

        return list
    }

    companion object {
        private const val serialVersionUID = -6254521894809367938L
    }
}
