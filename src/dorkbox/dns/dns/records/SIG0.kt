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

package dorkbox.dns.dns.records;

import java.security.PrivateKey;
import java.util.Date;

import dorkbox.dns.dns.utils.Options;
import dorkbox.dns.dns.constants.DnsRecordType;
import dorkbox.dns.dns.constants.DnsSection;

/**
 * Creates SIG(0) transaction signatures.
 *
 * @author Pasi Eronen
 * @author Brian Wellington
 */

public
class SIG0 {

    /**
     * The default validity period for outgoing SIG(0) signed messages.
     * Can be overriden by the sig0validity option.
     */
    private static final short VALIDITY = 300;

    private
    SIG0() { }

    /**
     * Sign a dnsMessage with SIG(0). The DNS key and private key must refer to the
     * same underlying cryptographic key.
     *
     * @param dnsMessage The dnsMessage to be signed
     * @param key The DNSKEY record to use as part of signing
     * @param privkey The PrivateKey to use when signing
     * @param previous If this dnsMessage is a response, the SIG(0) from the query
     */
    public static
    void signMessage(DnsMessage dnsMessage, KEYRecord key, PrivateKey privkey, SIGRecord previous) throws DNSSEC.DNSSECException {

        int validity = Options.intValue("sig0validity");
        if (validity < 0) {
            validity = VALIDITY;
        }

        long now = System.currentTimeMillis();
        Date timeSigned = new Date(now);
        Date timeExpires = new Date(now + validity * 1000);

        SIGRecord sig = DNSSEC.signMessage(dnsMessage, previous, key, privkey, timeSigned, timeExpires);

        dnsMessage.addRecord(sig, DnsSection.ADDITIONAL);
    }

    /**
     * Verify a dnsMessage using SIG(0).
     *
     * @param dnsMessage The dnsMessage to be signed
     * @param b An array containing the dnsMessage in unparsed form.  This is
     *         necessary since SIG(0) signs the dnsMessage in wire format, and we can't
     *         recreate the exact wire format (with the same name compression).
     * @param key The KEY record to verify the signature with.
     * @param previous If this dnsMessage is a response, the SIG(0) from the query
     */
    public static
    void verifyMessage(DnsMessage dnsMessage, byte[] b, KEYRecord key, SIGRecord previous) throws DNSSEC.DNSSECException {
        SIGRecord sig = null;
        DnsRecord[] additional = dnsMessage.getSectionArray(DnsSection.ADDITIONAL);
        for (int i = 0; i < additional.length; i++) {
            if (additional[i].getType() != DnsRecordType.SIG) {
                continue;
            }
            if (((SIGRecord) additional[i]).getTypeCovered() != 0) {
                continue;
            }
            sig = (SIGRecord) additional[i];
            break;
        }
        DNSSEC.verifyMessage(dnsMessage, b, sig, previous, key);
    }

}
