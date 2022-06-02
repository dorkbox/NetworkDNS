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
import dorkbox.dns.dns.utils.Tokenizer
import java.io.IOException

/**
 * Server Selection Record  - finds hosts running services in a domain.  An
 * SRV record will normally be named _&lt;service&gt;._&lt;protocol&gt;.domain
 * - examples would be _sips._tcp.example.org (for the secure SIP protocol) and
 * _http._tcp.example.com (if HTTP used SRV records)
 *
 * @author Brian Wellington
 */
class SRVRecord : DnsRecord {
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

    /**
     * Returns the port that the service runs on
     */
    var port = 0
        private set

    /**
     * Returns the host running that the service
     */
    override var additionalName: Name? = null


    internal constructor() {}

    override val `object`: DnsRecord
        get() = SRVRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        priority = `in`.readU16()
        weight = `in`.readU16()
        port = `in`.readU16()
        additionalName = Name(`in`)
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeU16(priority)
        out.writeU16(weight)
        out.writeU16(port)
        additionalName!!.toWire(out, null, canonical)
    }

    /**
     * Converts rdata to a String
     */
    override fun rrToString(sb: StringBuilder) {
        sb.append("$priority ")
        sb.append("$weight ")
        sb.append("$port ")
        sb.append(additionalName)
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        priority = st.getUInt16()
        weight = st.getUInt16()
        port = st.getUInt16()
        additionalName = st.getName(origin)
    }

    /**
     * Creates an SRV Record from the given data
     *
     * @param priority The priority of this SRV.  Records with lower priority
     * are preferred.
     * @param weight The weight, used to select between records at the same
     * priority.
     * @param port The TCP/UDP port that the service uses
     * @param target The host running the service
     */
    constructor(name: Name?, dclass: Int, ttl: Long, priority: Int, weight: Int, port: Int, target: Name?) : super(
        name!!, DnsRecordType.SRV, dclass, ttl
    ) {
        this.priority = checkU16("priority", priority)
        this.weight = checkU16("weight", weight)
        this.port = checkU16("port", port)
        additionalName = checkName("target", target!!)
    }

    companion object {
        private const val serialVersionUID = -3886460132387522052L
    }
}
