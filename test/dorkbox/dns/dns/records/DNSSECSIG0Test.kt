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
import dorkbox.dns.dns.constants.DnsClass
import dorkbox.dns.dns.records.SIG0.signMessage
import dorkbox.dns.dns.records.SIG0.verifyMessage
import junit.framework.TestCase
import java.security.KeyPairGenerator

class DNSSECSIG0Test : TestCase() {
    var algorithm = DNSSEC.Algorithm.RSASHA1
    var toSign = "The quick brown fox jumped over the lazy dog.".toByteArray()
    public override fun setUp() {}
    public override fun tearDown() {}
    @Throws(Exception::class)
    fun testSIG0() {
        val sig0zoneName = Name("sig0.invalid.")
        val sig0hostName = Name("sometext.sig0.invalid.")
        val rsagen = KeyPairGenerator.getInstance("RSA")
        val rsapair = rsagen.generateKeyPair()
        val privKey = rsapair.private
        val pubKey = rsapair.public
        val keyRecord = KEYRecord(
            sig0zoneName, DnsClass.IN, 0, KEYRecord.Flags.HOST, KEYRecord.Protocol.DNSSEC, DNSSEC.Algorithm.RSASHA1, pubKey
        )
        val txtRecord = TXTRecord(sig0hostName, DnsClass.IN, 0, "Hello World!")
        val updateMessage = Update(sig0zoneName)
        updateMessage.add(txtRecord)
        signMessage(updateMessage, keyRecord, privKey, null)
        val message = DnsMessage(updateMessage.toWire())
        verifyMessage(message, message.toWire(), keyRecord, null)
    }

    companion object {
        private const val SIGNATURE_ALGORITHM = "SHA1withRSA"
        private const val KEY_ALGORITHM = "RSA"
    }
}
