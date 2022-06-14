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
 * The NULL Record.  This has no defined purpose, but can be used to
 * hold arbitrary data.
 *
 * @author Brian Wellington
 */
class NULLRecord : DnsRecord {
    /**
     * Returns the contents of this record.
     */
    lateinit var data: ByteArray
        private set

    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = NULLRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        data = `in`.readByteArray()
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeByteArray(data)
    }

    override fun rrToString(sb: StringBuilder) {
        sb.append(unknownToString(data))
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        throw st.exception("no defined text format for NULL records")
    }

    /**
     * Creates a NULL record from the given data.
     *
     * @param data The contents of the record.
     */
    constructor(name: Name?, dclass: Int, ttl: Long, data: ByteArray) : super(name!!, DnsRecordType.NULL, dclass, ttl) {
        require(data.size <= 0xFFFF) { "data must be <65536 bytes" }
        this.data = data
    }

    companion object {
        private const val serialVersionUID = -5796493183235216538L
    }
}
