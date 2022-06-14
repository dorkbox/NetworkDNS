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
import dorkbox.dns.dns.utils.base16.toString
import java.io.IOException

/**
 * DLV - contains a Delegation Lookaside Validation record, which acts
 * as the equivalent of a DS record in a lookaside zone.
 *
 * @author David Blacka
 * @author Brian Wellington
 * @see DNSSEC
 *
 * @see DSRecord
 */
class DLVRecord : DnsRecord {
    /**
     * Returns the key's footprint.
     */
    var footprint = 0
        private set

    /**
     * Returns the key's algorithm.
     */
    var algorithm = 0
        private set

    /**
     * Returns the key's Digest ID.
     */
    var digestID = 0
        private set

    /**
     * Returns the binary hash of the key.
     */
    var digest: ByteArray = byteArrayOf()
        private set

    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = DLVRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        footprint = `in`.readU16()
        algorithm = `in`.readU8()
        digestID = `in`.readU8()
        digest = `in`.readByteArray()
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeU16(footprint)
        out.writeU8(algorithm)
        out.writeU8(digestID)
        if (digest.isNotEmpty()) {
            out.writeByteArray(digest)
        }
    }

    /**
     * Converts rdata to a String
     */
    override fun rrToString(sb: StringBuilder) {
        sb.append(footprint)
        sb.append(" ")
        sb.append(algorithm)
        sb.append(" ")
        sb.append(digestID)
        if (digest.isNotEmpty()) {
            sb.append(" ")
            sb.append(toString(digest))
        }
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        footprint = st.getUInt16()
        algorithm = st.getUInt8()
        digestID = st.getUInt8()
        digest = st.getHex(true)!!
    }

    /**
     * Creates a DLV Record from the given data
     *
     * @param footprint The original KEY record's footprint (keyid).
     * @param alg The original key algorithm.
     * @param digestid The digest id code.
     * @param digest A hash of the original key.
     */
    constructor(name: Name, dclass: Int, ttl: Long, footprint: Int, alg: Int, digestid: Int, digest: ByteArray) : super(
        name, DnsRecordType.DLV, dclass, ttl
    ) {
        this.footprint = checkU16("footprint", footprint)
        algorithm = checkU8("alg", alg)
        digestID = checkU8("digestid", digestid)
        this.digest = digest
    }

    companion object {
        const val SHA1_DIGEST_ID = DSRecord.Digest.SHA1
        const val SHA256_DIGEST_ID = DSRecord.Digest.SHA1
        private const val serialVersionUID = 1960742375677534148L
    }
}
