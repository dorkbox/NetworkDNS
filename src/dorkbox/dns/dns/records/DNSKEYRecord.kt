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

import dorkbox.dns.dns.Name
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.records.DNSSEC.Algorithm.value
import dorkbox.dns.dns.records.DNSSEC.fromPublicKey
import dorkbox.dns.dns.utils.Tokenizer
import java.io.IOException
import java.security.PublicKey

/**
 * Key - contains a cryptographic public key for use by DNS.
 * The data can be converted to objects implementing
 * java.security.interfaces.PublicKey
 *
 * @author Brian Wellington
 * @see DNSSEC
 */
class DNSKEYRecord : KEYBase {
    object Protocol {
        /**
         * Key will be used for DNSSEC
         */
        const val DNSSEC = 3
    }

    object Flags {
        /**
         * Key is a zone key
         */
        const val ZONE_KEY = 0x100

        /**
         * Key is a secure entry point key
         */
        const val SEP_KEY = 0x1

        /**
         * Key has been revoked
         */
        const val REVOKE = 0x80
    }

    internal constructor() {}

    override val `object`: DnsRecord
        get() = DNSKEYRecord()

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        flags = st.getUInt16()
        protocol = st.getUInt8()
        val algString = st.getString()
        algorithm = value(algString)
        if (algorithm < 0) {
            throw st.exception("Invalid algorithm: $algString")
        }

        key = st.getBase64(true)!!
    }

    /**
     * Creates a DNSKEY Record from the given data
     *
     * @param flags Flags describing the key's properties
     * @param proto The protocol that the key was created for
     * @param alg The key's algorithm
     * @param key Binary representation of the key
     */
    constructor(name: Name, dclass: Int, ttl: Long, flags: Int, proto: Int, alg: Int, key: ByteArray) : super(
        name, DnsRecordType.DNSKEY, dclass, ttl, flags, proto, alg, key
    )

    /**
     * Creates a DNSKEY Record from the given data
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
        name, DnsRecordType.DNSKEY, dclass, ttl, flags, proto, alg, fromPublicKey(key, alg)
    )

    companion object {
        private const val serialVersionUID = -8679800040426675002L
    }
}
