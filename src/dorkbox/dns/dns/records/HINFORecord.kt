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
import dorkbox.dns.dns.exceptions.TextParseException
import dorkbox.dns.dns.utils.Tokenizer
import java.io.IOException

/**
 * Host Information - describes the CPU and OS of a host
 *
 * @author Brian Wellington
 */
class HINFORecord : DnsRecord {
    private lateinit var cpu: ByteArray
    private lateinit var os: ByteArray

    internal constructor() {}

    override val `object`: DnsRecord
        get() = HINFORecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        cpu = `in`.readCountedString()
        os = `in`.readCountedString()
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeCountedString(cpu)
        out.writeCountedString(os)
    }

    /**
     * Converts to a string
     */
    override fun rrToString(sb: StringBuilder) {
        sb.append(byteArrayToString(cpu, true))
        sb.append(" ")
        sb.append(byteArrayToString(os, true))
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        try {
            cpu = byteArrayFromString(st.getString())
            os = byteArrayFromString(st.getString())
        } catch (e: TextParseException) {
            throw st.exception(e.message ?: "")
        }
    }

    /**
     * Creates an HINFO Record from the given data
     *
     * @param cpu A string describing the host's CPU
     * @param os A string describing the host's OS
     *
     * @throws IllegalArgumentException One of the strings has invalid escapes
     */
    constructor(name: Name?, dclass: Int, ttl: Long, cpu: String?, os: String?) : super(name!!, DnsRecordType.HINFO, dclass, ttl) {
        try {
            this.cpu = byteArrayFromString(cpu!!)
            this.os = byteArrayFromString(os!!)
        } catch (e: TextParseException) {
            throw IllegalArgumentException(e.message)
        }
    }

    /**
     * Returns the host's CPU
     */
    val cPU: String
        get() = byteArrayToString(cpu, false)

    /**
     * Returns the host's OS
     */
    val oS: String
        get() = byteArrayToString(os, false)

    companion object {
        private const val serialVersionUID = -4732870630947452112L
    }
}
