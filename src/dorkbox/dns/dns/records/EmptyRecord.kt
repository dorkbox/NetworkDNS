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
import dorkbox.dns.dns.utils.Tokenizer
import java.io.IOException

/**
 * A class implementing Records with no data; that is, records used in
 * the question section of messages and meta-records in dynamic update.
 *
 * @author Brian Wellington
 */
class EmptyRecord : DnsRecord() {
    override val dnsRecord: DnsRecord
        get() = EmptyRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {}
    override fun rrToString(sb: StringBuilder) {}
    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
    }

    companion object {
        private const val serialVersionUID = 3601852050646429582L
    }
}
