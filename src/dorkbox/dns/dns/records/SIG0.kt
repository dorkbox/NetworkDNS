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

import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.constants.DnsSection
import dorkbox.dns.dns.records.DNSSEC.DNSSECException
import dorkbox.dns.dns.records.DNSSEC.signMessage
import dorkbox.dns.dns.records.DNSSEC.verifyMessage
import dorkbox.dns.dns.utils.Options.intValue
import java.security.PrivateKey
import java.util.*

/**
 * Creates SIG(0) transaction signatures.
 *
 * @author Pasi Eronen
 * @author Brian Wellington
 */
object SIG0 {
    /**
     * The default validity period for outgoing SIG(0) signed messages.
     * Can be overriden by the sig0validity option.
     */
    private const val VALIDITY: Short = 300

    /**
     * Sign a dnsMessage with SIG(0). The DNS key and private key must refer to the
     * same underlying cryptographic key.
     *
     * @param dnsMessage The dnsMessage to be signed
     * @param key The DNSKEY record to use as part of signing
     * @param privkey The PrivateKey to use when signing
     * @param previous If this dnsMessage is a response, the SIG(0) from the query
     */
    @Throws(DNSSECException::class)
    fun signMessage(dnsMessage: DnsMessage, key: KEYRecord, privkey: PrivateKey, previous: SIGRecord?) {
        var validity = intValue("sig0validity")
        if (validity < 0) {
            validity = VALIDITY.toInt()
        }
        val now = System.currentTimeMillis()
        val timeSigned = Date(now)
        val timeExpires = Date(now + validity * 1000)
        val sig = signMessage(dnsMessage, previous, key, privkey, timeSigned, timeExpires)
        dnsMessage.addRecord(sig, DnsSection.ADDITIONAL)
    }

    /**
     * Verify a dnsMessage using SIG(0).
     *
     * @param dnsMessage The dnsMessage to be signed
     * @param b An array containing the dnsMessage in unparsed form.  This is
     * necessary since SIG(0) signs the dnsMessage in wire format, and we can't
     * recreate the exact wire format (with the same name compression).
     * @param key The KEY record to verify the signature with.
     * @param previous If this dnsMessage is a response, the SIG(0) from the query
     */
    @Throws(DNSSECException::class)
    fun verifyMessage(dnsMessage: DnsMessage, b: ByteArray?, key: KEYRecord?, previous: SIGRecord?) {
        var sig: SIGRecord? = null
        val additional = dnsMessage.getSectionArray(DnsSection.ADDITIONAL)
        for (i in additional.indices) {
            if (additional[i].type != DnsRecordType.SIG) {
                continue
            }
            if ((additional[i] as SIGRecord).typeCovered != 0) {
                continue
            }
            sig = additional[i] as SIGRecord
            break
        }
        verifyMessage(dnsMessage, b, sig!!, previous, key!!)
    }
}
