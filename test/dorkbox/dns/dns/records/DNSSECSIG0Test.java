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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsClass;
import junit.framework.TestCase;

public
class DNSSECSIG0Test extends TestCase {

    private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
    private static final String KEY_ALGORITHM = "RSA";
    int algorithm = DNSSEC.Algorithm.RSASHA1;
    byte[] toSign = "The quick brown fox jumped over the lazy dog.".getBytes();

    @Override
    public
    void setUp() {
    }

    @Override
    public
    void tearDown() {
    }

    public
    void testSIG0() throws Exception {
        Name sig0zoneName = new Name("sig0.invalid.");
        Name sig0hostName = new Name("sometext.sig0.invalid.");

        KeyPairGenerator rsagen = KeyPairGenerator.getInstance("RSA");
        KeyPair rsapair = rsagen.generateKeyPair();
        PrivateKey privKey = rsapair.getPrivate();
        PublicKey pubKey = rsapair.getPublic();

        KEYRecord keyRecord = new KEYRecord(sig0zoneName,
                                            DnsClass.IN,
                                            0,
                                            KEYRecord.Flags.HOST,
                                            KEYRecord.Protocol.DNSSEC,
                                            DNSSEC.Algorithm.RSASHA1,
                                            pubKey);
        TXTRecord txtRecord = new TXTRecord(sig0hostName, DnsClass.IN, 0, "Hello World!");
        Update updateMessage = new Update(sig0zoneName);
        updateMessage.add(txtRecord);

        SIG0.INSTANCE.signMessage(updateMessage, keyRecord, privKey, null);
        DnsMessage message = new DnsMessage(updateMessage.toWire());
        SIG0.INSTANCE.verifyMessage(message, message.toWire(), keyRecord, null);
    }
}
