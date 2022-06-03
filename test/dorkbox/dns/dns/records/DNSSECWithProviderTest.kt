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

import junit.framework.TestCase
import java.security.KeyPairGenerator
import java.security.Signature

class DNSSECWithProviderTest : TestCase() {
    var algorithm = DNSSEC.Algorithm.RSASHA1
    var toSign = "The quick brown fox jumped over the lazy dog.".toByteArray()
    public override fun setUp() {}
    public override fun tearDown() {}
    @Throws(Exception::class)
    fun testSignSoftware() {
        val keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM)
        keyPairGenerator.initialize(512)
        val keyPair = keyPairGenerator.generateKeyPair()
        val signer = Signature.getInstance(SIGNATURE_ALGORITHM)
        signer.initSign(keyPair.private)
        signer.update(toSign)
        val signature = signer.sign()
        assertNotNull(signature)

        // verify the signature
        val verifier = Signature.getInstance(SIGNATURE_ALGORITHM)
        verifier.initVerify(keyPair.public)
        verifier.update(toSign)
        val verify = verifier.verify(signature)
        assertTrue(verify)
    }

    companion object {
        private const val SIGNATURE_ALGORITHM = "SHA1withRSA"
        private const val KEY_ALGORITHM = "RSA"
    }
}
