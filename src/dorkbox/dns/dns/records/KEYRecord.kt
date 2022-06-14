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

import dorkbox.dns.dns.Mnemonic
import dorkbox.dns.dns.Name
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.records.DNSSEC.Algorithm.value
import dorkbox.dns.dns.records.DNSSEC.fromPublicKey
import dorkbox.dns.dns.utils.Tokenizer
import java.io.IOException
import java.security.PublicKey
import java.util.*

/**
 * Key - contains a cryptographic public key.  The data can be converted
 * to objects implementing java.security.interfaces.PublicKey
 *
 * @author Brian Wellington
 * @see DNSSEC
 */
class KEYRecord : KEYBase {
    object Protocol {
        /**
         * No defined protocol.
         */
        const val NONE = 0

        /**
         * Transaction Level Security
         */
        const val TLS = 1

        /**
         * Email
         */
        const val EMAIL = 2

        /**
         * DNSSEC
         */
        const val DNSSEC = 3

        /**
         * IPSEC Control
         */
        const val IPSEC = 4

        /**
         * Any protocol
         */
        const val ANY = 255
        private val protocols = Mnemonic("KEY protocol", Mnemonic.CASE_UPPER)

        init {
            protocols.setMaximum(0xFF)
            protocols.setNumericAllowed(true)
            protocols.add(NONE, "NONE")
            protocols.add(TLS, "TLS")
            protocols.add(EMAIL, "EMAIL")
            protocols.add(DNSSEC, "DNSSEC")
            protocols.add(IPSEC, "IPSEC")
            protocols.add(ANY, "ANY")
        }

        /**
         * Converts an KEY protocol value into its textual representation
         */
        fun string(type: Int): String {
            return protocols.getText(type)
        }

        /**
         * Converts a textual representation of a KEY protocol into its
         * numeric code.  Integers in the range 0..255 are also accepted.
         *
         * @param s The textual representation of the protocol
         *
         * @return The protocol code, or -1 on error.
         */
        fun value(s: String?): Int {
            return protocols.getValue(s!!)
        }
    }

    object Flags {
        /**
         * KEY cannot be used for confidentiality
         */
        const val NOCONF = 0x4000

        /**
         * KEY cannot be used for authentication
         */
        const val NOAUTH = 0x8000

        /**
         * No key present
         */
        const val NOKEY = 0xC000

        /**
         * Bitmask of the use fields
         */
        const val USE_MASK = 0xC000

        /**
         * Flag 2 (unused)
         */
        const val FLAG2 = 0x2000

        /**
         * Flags extension
         */
        const val EXTEND = 0x1000

        /**
         * Flag 4 (unused)
         */
        const val FLAG4 = 0x0800

        /**
         * Flag 5 (unused)
         */
        const val FLAG5 = 0x0400

        /**
         * Key is owned by a user.
         */
        const val USER = 0x0000

        /**
         * Key is owned by a zone.
         */
        const val ZONE = 0x0100

        /**
         * Key is owned by a host.
         */
        const val HOST = 0x0200

        /**
         * Key owner type 3 (reserved).
         */
        const val NTYP3 = 0x0300

        /**
         * Key owner bitmask.
         */
        const val OWNER_MASK = 0x0300

        /**
         * Flag 8 (unused)
         */
        const val FLAG8 = 0x0080

        /**
         * Flag 9 (unused)
         */
        const val FLAG9 = 0x0040

        /**
         * Flag 10 (unused)
         */
        const val FLAG10 = 0x0020

        /**
         * Flag 11 (unused)
         */
        const val FLAG11 = 0x0010

        /**
         * Signatory value 0
         */
        const val SIG0 = 0

        /**
         * Signatory value 1
         */
        const val SIG1 = 1

        /**
         * Signatory value 2
         */
        const val SIG2 = 2

        /**
         * Signatory value 3
         */
        const val SIG3 = 3

        /**
         * Signatory value 4
         */
        const val SIG4 = 4

        /**
         * Signatory value 5
         */
        const val SIG5 = 5

        /**
         * Signatory value 6
         */
        const val SIG6 = 6

        /**
         * Signatory value 7
         */
        const val SIG7 = 7

        /**
         * Signatory value 8
         */
        const val SIG8 = 8

        /**
         * Signatory value 9
         */
        const val SIG9 = 9

        /**
         * Signatory value 10
         */
        const val SIG10 = 10

        /**
         * Signatory value 11
         */
        const val SIG11 = 11

        /**
         * Signatory value 12
         */
        const val SIG12 = 12

        /**
         * Signatory value 13
         */
        const val SIG13 = 13

        /**
         * Signatory value 14
         */
        const val SIG14 = 14

        /**
         * Signatory value 15
         */
        const val SIG15 = 15
        private val flags = Mnemonic("KEY flags", Mnemonic.CASE_UPPER)

        init {
            flags.setMaximum(0xFFFF)
            flags.setNumericAllowed(false)
            flags.add(NOCONF, "NOCONF")
            flags.add(NOAUTH, "NOAUTH")
            flags.add(NOKEY, "NOKEY")
            flags.add(FLAG2, "FLAG2")
            flags.add(EXTEND, "EXTEND")
            flags.add(FLAG4, "FLAG4")
            flags.add(FLAG5, "FLAG5")
            flags.add(USER, "USER")
            flags.add(ZONE, "ZONE")
            flags.add(HOST, "HOST")
            flags.add(NTYP3, "NTYP3")
            flags.add(FLAG8, "FLAG8")
            flags.add(FLAG9, "FLAG9")
            flags.add(FLAG10, "FLAG10")
            flags.add(FLAG11, "FLAG11")
            flags.add(SIG0, "SIG0")
            flags.add(SIG1, "SIG1")
            flags.add(SIG2, "SIG2")
            flags.add(SIG3, "SIG3")
            flags.add(SIG4, "SIG4")
            flags.add(SIG5, "SIG5")
            flags.add(SIG6, "SIG6")
            flags.add(SIG7, "SIG7")
            flags.add(SIG8, "SIG8")
            flags.add(SIG9, "SIG9")
            flags.add(SIG10, "SIG10")
            flags.add(SIG11, "SIG11")
            flags.add(SIG12, "SIG12")
            flags.add(SIG13, "SIG13")
            flags.add(SIG14, "SIG14")
            flags.add(SIG15, "SIG15")
        }

        /**
         * Converts a textual representation of KEY flags into its
         * numeric code.  Integers in the range 0..65535 are also accepted.
         *
         * @param s The textual representation of the protocol
         *
         * @return The protocol code, or -1 on error.
         */
        fun value(s: String): Int {
            var value: Int
            try {
                value = s.toInt()
                return if (value >= 0 && value <= 0xFFFF) {
                    value
                } else -1
            } catch (e: NumberFormatException) {
            }
            val st = StringTokenizer(s, "|")
            value = 0
            while (st.hasMoreTokens()) {
                val `val` = flags.getValue(st.nextToken())
                if (`val` < 0) {
                    return -1
                }
                value = value or `val`
            }
            return value
        }
    }

    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = KEYRecord()

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        val flagString = st.getIdentifier()
        flags = Flags.value(flagString)
        if (flags < 0) {
            throw st.exception("Invalid flags: $flagString")
        }
        val protoString = st.getIdentifier()
        protocol = Protocol.value(protoString)
        if (protocol < 0) {
            throw st.exception("Invalid protocol: $protoString")
        }
        val algString = st.getIdentifier()
        algorithm = value(algString)
        if (algorithm < 0) {
            throw st.exception("Invalid algorithm: $algString")
        }

        /* If this is a null KEY, there's no key data */
        key = if (flags and Flags.USE_MASK == Flags.NOKEY) {
            null
        } else {
            st.base64!!
        }
    }

    /**
     * Creates a KEY Record from the given data
     *
     * @param flags Flags describing the key's properties
     * @param proto The protocol that the key was created for
     * @param alg The key's algorithm
     * @param key Binary data representing the key
     */
    constructor(name: Name, dclass: Int, ttl: Long, flags: Int, proto: Int, alg: Int, key: ByteArray?) : super(
        name, DnsRecordType.KEY, dclass, ttl, flags, proto, alg, key!!
    )

    /**
     * Creates a KEY Record from the given data
     *
     * @param flags Flags describing the key's properties
     * @param proto The protocol that the key was created for
     * @param alg The key's algorithm
     * @param key The key as a PublicKey
     *
     * @throws DNSSEC.DNSSECException The PublicKey could not be converted into DNS
     * format.
     */
    constructor(name: Name, dclass: Int, ttl: Long, flags: Int, proto: Int, alg: Int, key: PublicKey) : super(
        name, DnsRecordType.KEY, dclass, ttl, flags, proto, alg, fromPublicKey(key, alg)
    )

    companion object {
        private const val serialVersionUID = 6385613447571488906L

        /**
         * This key cannot be used for confidentiality (encryption)
         */
        const val FLAG_NOCONF = Flags.NOCONF

        /**
         * This key cannot be used for authentication
         */
        const val FLAG_NOAUTH = Flags.NOAUTH
        /* flags */
        /**
         * This key cannot be used for authentication or confidentiality
         */
        const val FLAG_NOKEY = Flags.NOKEY

        /**
         * A zone key
         */
        const val OWNER_ZONE = Flags.ZONE

        /**
         * A host/end entity key
         */
        const val OWNER_HOST = Flags.HOST

        /**
         * A user key
         */
        const val OWNER_USER = Flags.USER

        /**
         * Key was created for use with transaction level security
         */
        const val PROTOCOL_TLS = Protocol.TLS

        /**
         * Key was created for use with email
         */
        const val PROTOCOL_EMAIL = Protocol.EMAIL
        /* protocols */
        /**
         * Key was created for use with DNSSEC
         */
        const val PROTOCOL_DNSSEC = Protocol.DNSSEC

        /**
         * Key was created for use with IPSEC
         */
        const val PROTOCOL_IPSEC = Protocol.IPSEC

        /**
         * Key was created for use with any protocol
         */
        const val PROTOCOL_ANY = Protocol.ANY
    }
}
