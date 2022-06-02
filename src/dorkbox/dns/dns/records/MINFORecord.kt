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
 * Mailbox information Record - lists the address responsible for a mailing
 * list/mailbox and the address to receive error messages relating to the
 * mailing list/mailbox.
 *
 * @author Brian Wellington
 */
class MINFORecord : DnsRecord {
    /**
     * Gets the address responsible for the mailing list/mailbox.
     */
    var responsibleAddress: Name? = null
        private set

    /**
     * Gets the address to receive error messages relating to the mailing
     * list/mailbox.
     */
    var errorAddress: Name? = null
        private set

    internal constructor() {}

    override val `object`: DnsRecord
        get() = MINFORecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        responsibleAddress = Name(`in`)
        errorAddress = Name(`in`)
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        responsibleAddress!!.toWire(out, null, canonical)
        errorAddress!!.toWire(out, null, canonical)
    }

    /**
     * Converts the MINFO Record to a String
     */
    override fun rrToString(sb: StringBuilder) {
        sb.append(responsibleAddress)
        sb.append(" ")
        sb.append(errorAddress)
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        responsibleAddress = st.getName(origin)
        errorAddress = st.getName(origin)
    }

    /**
     * Creates an MINFO Record from the given data
     *
     * @param responsibleAddress The address responsible for the
     * mailing list/mailbox.
     * @param errorAddress The address to receive error messages relating to the
     * mailing list/mailbox.
     */
    constructor(name: Name?, dclass: Int, ttl: Long, responsibleAddress: Name?, errorAddress: Name?) : super(
        name!!, DnsRecordType.MINFO, dclass, ttl
    ) {
        this.responsibleAddress = checkName("responsibleAddress", responsibleAddress!!)
        this.errorAddress = checkName("errorAddress", errorAddress!!)
    }

    companion object {
        private const val serialVersionUID = -3962147172340353796L
    }
}
