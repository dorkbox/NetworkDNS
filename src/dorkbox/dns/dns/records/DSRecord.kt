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
import dorkbox.dns.dns.records.DNSSEC.generateDSDigest
import dorkbox.dns.dns.utils.Tokenizer
import dorkbox.dns.dns.utils.base16.toString
import java.io.IOException

/**
 * DS - contains a Delegation Signer record, which acts as a
 * placeholder for KEY records in the parent zone.
 *
 * @author David Blacka
 * @author Brian Wellington
 * @see DNSSEC
 */
class DSRecord : DnsRecord {
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
    var digest: ByteArray? = null
        private set

    object Digest {
        /**
         * SHA-1
         */
        const val SHA1 = 1

        /**
         * SHA-256
         */
        const val SHA256 = 2

        /**
         * GOST R 34.11-94
         */
        const val GOST3411 = 3

        /**
         * SHA-384
         */
        const val SHA384 = 4
    }

    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = DSRecord()

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

        if (digest != null) {
            out.writeByteArray(digest!!)
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
        if (digest != null) {
            sb.append(" ")
            sb.append(toString(digest!!))
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
     * Creates a DS Record from the given data
     *
     * @param digestid The digest id code.
     * @param key The key to digest
     */
    constructor(name: Name, dclass: Int, ttl: Long, digestid: Int, key: DNSKEYRecord) : this(
        name,
        dclass,
        ttl,
        key.footprint,
        key.algorithm,
        digestid,
        generateDSDigest(key, digestid)
    ) {
    }

    /**
     * Creates a DS Record from the given data
     *
     * @param footprint The original KEY record's footprint (keyid).
     * @param alg The original key algorithm.
     * @param digestid The digest id code.
     * @param digest A hash of the original key.
     */
    constructor(name: Name, dclass: Int, ttl: Long, footprint: Int, alg: Int, digestid: Int, digest: ByteArray?) : super(
        name, DnsRecordType.DS, dclass, ttl
    ) {
        this.footprint = checkU16("footprint", footprint)
        algorithm = checkU8("alg", alg)
        digestID = checkU8("digestid", digestid)
        this.digest = digest
    }

    companion object {
        const val SHA1_DIGEST_ID = Digest.SHA1
        const val SHA256_DIGEST_ID = Digest.SHA256
        const val GOST3411_DIGEST_ID = Digest.GOST3411
        const val SHA384_DIGEST_ID = Digest.SHA384
        private const val serialVersionUID = -9001819329700081493L
    }
}
