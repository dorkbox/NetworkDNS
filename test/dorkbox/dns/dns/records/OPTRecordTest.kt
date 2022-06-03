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

class OPTRecordTest : TestCase() {
    fun testForNoEqualityWithDifferentEDNS_Versions() {
        val optRecordOne = OPTRecord(DEFAULT_PAYLOAD_SIZE, DEFAULT_EDNS_RCODE, 0)
        val optRecordTwo = OPTRecord(DEFAULT_PAYLOAD_SIZE, DEFAULT_EDNS_RCODE, 1)
        assertNotEqual(optRecordOne, optRecordTwo)
    }

    private fun assertNotEqual(optRecordOne: OPTRecord, optRecordTwo: OPTRecord) {
        assertTrue("Expecting no equality of $optRecordOne compared to $optRecordTwo", !optRecordOne.equals(optRecordTwo))
        assertTrue("Expecting no equality of $optRecordTwo compared to $optRecordOne", !optRecordTwo.equals(optRecordOne))
    }

    fun testForNoEqualityWithDifferentEDNS_RCodes() {
        val optRecordOne = OPTRecord(DEFAULT_PAYLOAD_SIZE, 0, DEFAULT_EDNS_VERSION)
        val optRecordTwo = OPTRecord(DEFAULT_PAYLOAD_SIZE, 1, DEFAULT_EDNS_VERSION)
        assertNotEqual(optRecordOne, optRecordTwo)
    }

    fun testForEquality() {
        val optRecordOne = OPTRecord(DEFAULT_PAYLOAD_SIZE, DEFAULT_EDNS_RCODE, DEFAULT_EDNS_VERSION)
        val optRecordTwo = OPTRecord(DEFAULT_PAYLOAD_SIZE, DEFAULT_EDNS_RCODE, DEFAULT_EDNS_VERSION)
        assertEquals(optRecordOne, optRecordTwo)
        assertEquals(optRecordTwo, optRecordOne)
    }

    companion object {
        private const val DEFAULT_EDNS_RCODE = 0
        private const val DEFAULT_EDNS_VERSION = 0
        private const val DEFAULT_PAYLOAD_SIZE = 1024
    }
}
