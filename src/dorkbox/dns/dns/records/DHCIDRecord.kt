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
import java.util.*

/**
 * DHCID - Dynamic Host Configuration Protocol (DHCP) ID (RFC 4701)
 *
 * @author Brian Wellington
 */
class DHCIDRecord : DnsRecord {
    /**
     * Returns the binary data.
     */
    var data: ByteArray = byteArrayOf()
        private set

    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = DHCIDRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        data = `in`.readByteArray()
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeByteArray(data)
    }

    override fun rrToString(sb: StringBuilder) {
        sb.append(Base64.getEncoder().encodeToString(data))
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        data = st.getBase64(true)!!
    }

    /**
     * Creates an DHCID Record from the given data
     *
     * @param data The binary data, which is opaque to DNS.
     */
    constructor(name: Name, dclass: Int, ttl: Long, data: ByteArray) : super(name, DnsRecordType.DHCID, dclass, ttl) {
        this.data = data
    }

    companion object {
        private const val serialVersionUID = -8214820200808997707L
    }
}
