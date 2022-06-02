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
 * A class implementing Records of unknown and/or unimplemented types.  This
 * class can only be initialized using static Record initializers.
 *
 * @author Brian Wellington
 */
class UNKRecord internal constructor() : DnsRecord() {
    /**
     * Returns the contents of this record.
     */
    lateinit var data: ByteArray
        private set

    override val `object`: DnsRecord
        get() = UNKRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        data = `in`.readByteArray()
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeByteArray(data)
    }

    /**
     * Converts this Record to the String "unknown format"
     */
    override fun rrToString(sb: StringBuilder) {
        sb.append(unknownToString(data))
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        throw st.exception("invalid unknown RR encoding")
    }

    companion object {
        private const val serialVersionUID = -4193583311594626915L
    }
}
