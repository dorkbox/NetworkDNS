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
import java.util.*

/**
 * Recource Record Signature - An RRSIG provides the digital signature of an
 * RRset, so that the data can be authenticated by a DNSSEC-capable resolver.
 * The signature is generated by a key contained in a DNSKEY Record.
 *
 * @author Brian Wellington
 * @see RRset
 *
 * @see DNSSEC
 *
 * @see KEYRecord
 */
class RRSIGRecord : SIGBase {
    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = RRSIGRecord()

    /**
     * Creates an RRSIG Record from the given data
     *
     * @param covered The RRset type covered by this signature
     * @param alg The cryptographic algorithm of the key that generated the
     * signature
     * @param origttl The original TTL of the RRset
     * @param expire The time at which the signature expires
     * @param timeSigned The time at which this signature was generated
     * @param footprint The footprint/key id of the signing key.
     * @param signer The owner of the signing key
     * @param signature Binary data representing the signature
     */
    constructor(
        name: Name,
        dclass: Int,
        ttl: Long,
        covered: Int,
        alg: Int,
        origttl: Long,
        expire: Date,
        timeSigned: Date,
        footprint: Int,
        signer: Name,
        signature: ByteArray
    ) : super(name, DnsRecordType.RRSIG, dclass, ttl, covered, alg, origttl, expire, timeSigned, footprint, signer, signature) {
    }

    companion object {
        private const val serialVersionUID = -2609150673537226317L
    }
}
