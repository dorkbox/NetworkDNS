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
import dorkbox.dns.dns.Mnemonic
import dorkbox.dns.dns.Name
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.records.DNSSEC.Algorithm.value
import dorkbox.dns.dns.utils.Options.check
import dorkbox.dns.dns.utils.Tokenizer
import dorkbox.os.OS.LINE_SEPARATOR
import java.io.IOException
import java.util.*

/**
 * Certificate Record  - Stores a certificate associated with a name.  The
 * certificate might also be associated with a KEYRecord.
 *
 * @author Brian Wellington
 * @see KEYRecord
 */
class CERTRecord : DnsRecord {
    /**
     * Returns the type of certificate
     */
    var certType = 0
        private set

    /**
     * Returns the ID of the associated KEYRecord, if present
     */
    var keyTag = 0
        private set

    /**
     * Returns the algorithm of the associated KEYRecord, if present
     */
    var algorithm = 0
        private set

    /**
     * Returns the binary representation of the certificate
     */
    var cert: ByteArray? = null
        private set

    object CertificateType {
        /**
         * PKIX (X.509v3)
         */
        const val PKIX = 1

        /**
         * Simple Public Key Infrastructure
         */
        const val SPKI = 2

        /**
         * Pretty Good Privacy
         */
        const val PGP = 3

        /**
         * URL of an X.509 data object
         */
        const val IPKIX = 4

        /**
         * URL of an SPKI certificate
         */
        const val ISPKI = 5

        /**
         * Fingerprint and URL of an OpenPGP packet
         */
        const val IPGP = 6

        /**
         * Attribute Certificate
         */
        const val ACPKIX = 7

        /**
         * URL of an Attribute Certificate
         */
        const val IACPKIX = 8

        /**
         * Certificate format defined by URI
         */
        const val URI = 253

        /**
         * Certificate format defined by OID
         */
        const val OID = 254
        private val types = Mnemonic("Certificate type", Mnemonic.CASE_UPPER)

        init {
            types.setMaximum(0xFFFF)
            types.setNumericAllowed(true)
            types.add(PKIX, "PKIX")
            types.add(SPKI, "SPKI")
            types.add(PGP, "PGP")
            types.add(PKIX, "IPKIX")
            types.add(SPKI, "ISPKI")
            types.add(PGP, "IPGP")
            types.add(PGP, "ACPKIX")
            types.add(PGP, "IACPKIX")
            types.add(URI, "URI")
            types.add(OID, "OID")
        }

        /**
         * Converts a certificate type into its textual representation
         */
        fun string(type: Int): String {
            return types.getText(type)
        }

        /**
         * Converts a textual representation of an certificate type into its
         * numeric code.  Integers in the range 0..65535 are also accepted.
         *
         * @param s The textual representation of the algorithm
         *
         * @return The algorithm code, or -1 on error.
         */
        fun value(s: String?): Int {
            return types.getValue(s!!)
        }
    }

    internal constructor() {}

    override val `object`: DnsRecord
        get() = CERTRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        certType = `in`.readU16()
        keyTag = `in`.readU16()
        algorithm = `in`.readU8()
        cert = `in`.readByteArray()
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeU16(certType)
        out.writeU16(keyTag)
        out.writeU8(algorithm)
        out.writeByteArray(cert!!)
    }

    /**
     * Converts rdata to a String
     */
    override fun rrToString(sb: StringBuilder) {
        sb.append(certType)
        sb.append(" ")
        sb.append(keyTag)
        sb.append(" ")
        sb.append(algorithm)
        if (cert != null) {
            if (check("multiline")) {
                sb.append(LINE_SEPARATOR)
                sb.append(Base64.getMimeEncoder().encodeToString(cert))
            } else {
                sb.append(Base64.getEncoder().encodeToString(cert))
            }
        }
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        val certTypeString = st.getString()
        certType = CertificateType.value(certTypeString)
        if (certType < 0) {
            throw st.exception("Invalid certificate type: $certTypeString")
        }
        keyTag = st.getUInt16()
        val algString = st.getString()
        algorithm = value(algString)
        if (algorithm < 0) {
            throw st.exception("Invalid algorithm: $algString")
        }
        cert = st.getBase64(true)!!
    }

    /**
     * Creates a CERT Record from the given data
     *
     * @param certType The type of certificate (see constants)
     * @param keyTag The ID of the associated KEYRecord, if present
     * @param alg The algorithm of the associated KEYRecord, if present
     * @param cert Binary data representing the certificate
     */
    constructor(name: Name, dclass: Int, ttl: Long, certType: Int, keyTag: Int, alg: Int, cert: ByteArray) : super(
        name, DnsRecordType.CERT, dclass, ttl
    ) {
        this.certType = checkU16("certType", certType)
        this.keyTag = checkU16("keyTag", keyTag)
        algorithm = checkU8("alg", alg)
        this.cert = cert
    }

    companion object {
        /**
         * PKIX (X.509v3)
         */
        const val PKIX = CertificateType.PKIX

        /**
         * Simple Public Key Infrastructure
         */
        const val SPKI = CertificateType.SPKI

        /**
         * Pretty Good Privacy
         */
        const val PGP = CertificateType.PGP

        /**
         * Certificate format defined by URI
         */
        const val URI = CertificateType.URI

        /**
         * Certificate format defined by IOD
         */
        const val OID = CertificateType.OID
        private const val serialVersionUID = 4763014646517016835L
    }
}
