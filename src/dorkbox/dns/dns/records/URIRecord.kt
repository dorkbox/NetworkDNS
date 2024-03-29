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
 * Uniform Resource Identifier (URI) DNS Resource Record
 *
 * @author Anthony Kirby
 * @see [http://tools.ietf.org/html/draft-faltstrom-uri](http://tools.ietf.org/html/draft-faltstrom-uri)
 */
class URIRecord : DnsRecord {
    /**
     * Returns the priority
     */
    var priority = 0
        private set

    /**
     * Returns the weight
     */
    var weight = 0
        private set

    private var target: ByteArray

    internal constructor() {
        target = byteArrayOf()
    }

    override val dnsRecord: DnsRecord
        get() = URIRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        priority = `in`.readU16()
        weight = `in`.readU16()
        target = `in`.readByteArray()
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeU16(priority)
        out.writeU16(weight)
        out.writeByteArray(target)
    }

    /**
     * Converts rdata to a String
     */
    override fun rrToString(sb: StringBuilder) {
        sb.append("$priority ")
        sb.append("$weight ")
        sb.append(byteArrayToString(target, true))
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        priority = st.getUInt16()
        weight = st.getUInt16()
        target = try {
            byteArrayFromString(st.getString())
        } catch (e: TextParseException) {
            throw st.exception(e.message ?: "")
        }
    }

    /**
     * Creates a URI Record from the given data
     *
     * @param priority The priority of this URI.  Records with lower priority
     * are preferred.
     * @param weight The weight, used to select between records at the same
     * priority.
     * @param target The host/port running the service
     */
    constructor(name: Name?, dclass: Int, ttl: Long, priority: Int, weight: Int, target: String?) : super(
        name!!, DnsRecordType.URI, dclass, ttl
    ) {
        this.priority = checkU16("priority", priority)
        this.weight = checkU16("weight", weight)
        try {
            this.target = byteArrayFromString(target!!)
        } catch (e: TextParseException) {
            throw IllegalArgumentException(e.message)
        }
    }

    /**
     * Returns the target URI
     */
    fun getTarget(): String {
        return byteArrayToString(target, false)
    }

    companion object {
        private const val serialVersionUID = 7955422413971804232L
    }
}
