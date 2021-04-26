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
import java.security.Signature;

import dorkbox.dns.dns.records.DNSSEC;
import junit.framework.TestCase;


public
class DNSSECWithProviderTest extends TestCase {

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
    void testSignSoftware() throws Exception {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGenerator.initialize(512);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        Signature signer = Signature.getInstance(SIGNATURE_ALGORITHM);
        signer.initSign(keyPair.getPrivate());
        signer.update(toSign);
        byte[] signature = signer.sign();
        assertNotNull(signature);

        // verify the signature
        Signature verifier = Signature.getInstance(SIGNATURE_ALGORITHM);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(toSign);
        boolean verify = verifier.verify(signature);
        assertTrue(verify);

    }
}
