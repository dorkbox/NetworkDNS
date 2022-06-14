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
 * S/MIME cert association, draft-ietf-dane-smime.
 *
 * @author Brian Wellington
 */
class SMIMEARecord : DnsRecord {
    /**
     * Returns the certificate usage of the SMIMEA record
     */
    // Note; these are copied from the TLSA type.
    var certificateUsage = 0
        private set

    /**
     * Returns the selector of the SMIMEA record
     */
    var selector = 0
        private set

    /**
     * Returns the matching type of the SMIMEA record
     */
    var matchingType = 0
        private set

    /**
     * Returns the certificate associate data of this SMIMEA record
     */
    var certificateAssociationData: ByteArray? = null
        private set

    object CertificateUsage {
        const val CA_CONSTRAINT = 0
        const val SERVICE_CERTIFICATE_CONSTRAINT = 1
        const val TRUST_ANCHOR_ASSERTION = 2
        const val DOMAIN_ISSUED_CERTIFICATE = 3
    }

    object Selector {
        /**
         * Full certificate; the Certificate binary structure defined in
         * [RFC5280]
         */
        const val FULL_CERTIFICATE = 0

        /**
         * SubjectPublicKeyInfo; DER-encoded binary structure defined in
         * [RFC5280]
         */
        const val SUBJECT_PUBLIC_KEY_INFO = 1
    }

    object MatchingType {
        /**
         * Exact match on selected content
         */
        const val EXACT = 0

        /**
         * SHA-256 hash of selected content [RFC6234]
         */
        const val SHA256 = 1

        /**
         * SHA-512 hash of selected content [RFC6234]
         */
        const val SHA512 = 2
    }

    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = SMIMEARecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        certificateUsage = `in`.readU8()
        selector = `in`.readU8()
        matchingType = `in`.readU8()
        certificateAssociationData = `in`.readByteArray()
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeU8(certificateUsage)
        out.writeU8(selector)
        out.writeU8(matchingType)
        out.writeByteArray(certificateAssociationData!!)
    }

    /**
     * Converts rdata to a String
     */
    override fun rrToString(sb: StringBuilder) {
        sb.append(certificateUsage)
        sb.append(" ")
        sb.append(selector)
        sb.append(" ")
        sb.append(matchingType)
        sb.append(" ")
        sb.append(toString(certificateAssociationData!!))
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        certificateUsage = st.getUInt8()
        selector = st.getUInt8()
        matchingType = st.getUInt8()
        certificateAssociationData = st.hex
    }

    /**
     * Creates an SMIMEA Record from the given data
     *
     * @param certificateUsage The provided association that will be used to
     * match the certificate presented in the S/MIME handshake.
     * @param selector The part of the S/MIME certificate presented by the server
     * that will be matched against the association data.
     * @param matchingType How the certificate association is presented.
     * @param certificateAssociationData The "certificate association data" to be
     * matched.
     */
    constructor(
        name: Name?,
        dclass: Int,
        ttl: Long,
        certificateUsage: Int,
        selector: Int,
        matchingType: Int,
        certificateAssociationData: ByteArray?
    ) : super(
        name!!, DnsRecordType.SMIMEA, dclass, ttl
    ) {
        this.certificateUsage = checkU8("certificateUsage", certificateUsage)
        this.selector = checkU8("selector", selector)
        this.matchingType = checkU8("matchingType", matchingType)
        this.certificateAssociationData = checkByteArrayLength("certificateAssociationData", certificateAssociationData!!, 0xFFFF)
    }

    companion object {
        private const val serialVersionUID = 1640247915216425235L
    }
}
