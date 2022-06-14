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
 * Responsible Person Record - lists the mail address of a responsible person
 * and a domain where TXT records are available.
 *
 * @author Tom Scola (tscola@research.att.com)
 * @author Brian Wellington
 */
class RPRecord : DnsRecord {
    /**
     * Gets the mailbox address of the RP Record
     */
    var mailbox: Name? = null
        private set

    /**
     * Gets the text domain info of the RP Record
     */
    var textDomain: Name? = null
        private set

    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = RPRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        mailbox = Name(`in`)
        textDomain = Name(`in`)
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        mailbox!!.toWire(out, null, canonical)
        textDomain!!.toWire(out, null, canonical)
    }

    /**
     * Converts the RP Record to a String
     */
    override fun rrToString(sb: StringBuilder) {
        sb.append(mailbox)
        sb.append(" ")
        sb.append(textDomain)
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        mailbox = st.getName(origin)
        textDomain = st.getName(origin)
    }

    /**
     * Creates an RP Record from the given data
     *
     * @param mailbox The responsible person
     * @param textDomain The address where TXT records can be found
     */
    constructor(name: Name?, dclass: Int, ttl: Long, mailbox: Name?, textDomain: Name?) : super(
        name!!, DnsRecordType.RP, dclass, ttl
    ) {
        this.mailbox = checkName("mailbox", mailbox!!)
        this.textDomain = checkName("textDomain", textDomain!!)
    }

    companion object {
        private const val serialVersionUID = 8124584364211337460L
    }
}
