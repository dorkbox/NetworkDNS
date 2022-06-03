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

import dorkbox.dns.dns.Name.Companion.fromString
import dorkbox.dns.dns.constants.DnsClass
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.constants.DnsResponseCode
import dorkbox.dns.dns.constants.DnsSection
import dorkbox.dns.dns.constants.Flags
import dorkbox.dns.dns.exceptions.TextParseException
import dorkbox.dns.dns.records.DnsMessage.Companion.newQuery
import dorkbox.dns.dns.records.DnsRecord.Companion.fromString
import dorkbox.dns.dns.records.DnsRecord.Companion.newRecord
import dorkbox.dns.dns.records.TSIG.Companion.HMAC_SHA256
import junit.framework.TestCase
import java.io.IOException

class TSIGTest : TestCase() {
    @Throws(TextParseException::class, IOException::class)
    fun test_TSIG_query() {
        val key = TSIG(HMAC_SHA256, "example.", "12345678")
        val qname = fromString("www.example.")
        val rec = newRecord(qname, DnsRecordType.A, DnsClass.IN, 0L)
        val msg = newQuery(rec)
        msg.setTSIG(key, DnsResponseCode.NOERROR, null)
        val bytes = msg.toWire(512)
        assertEquals(bytes[11].toInt(), 1)
        val parsed = DnsMessage(bytes)
        val result = key.verify(parsed, bytes, null)
        assertEquals(result, DnsResponseCode.NOERROR)
        assertTrue(parsed.isSigned)
    }

    @Throws(TextParseException::class, IOException::class)
    fun test_TSIG_response() {
        val key = TSIG(HMAC_SHA256, "example.", "12345678")
        val qname = fromString("www.example.")
        val question = newRecord(qname, DnsRecordType.A, DnsClass.IN, 0L)
        val query = newQuery(question)
        query.setTSIG(key, DnsResponseCode.NOERROR, null)
        val qbytes = query.toWire()
        val qparsed = DnsMessage(qbytes)
        val response = DnsMessage(
            query.header.iD
        )
        response.setTSIG(key, DnsResponseCode.NOERROR, qparsed.tSIG)
        response.header.setFlag(Flags.QR)
        response.addRecord(question, DnsSection.QUESTION)
        val answer = fromString(qname, DnsRecordType.A, DnsClass.IN, 300, "1.2.3.4", null)
        response.addRecord(answer, DnsSection.ANSWER)
        val bytes = response.toWire(512)
        val parsed = DnsMessage(bytes)
        val result = key.verify(parsed, bytes, qparsed.tSIG)
        assertEquals(result, DnsResponseCode.NOERROR)
        assertTrue(parsed.isSigned)
    }

    @Throws(TextParseException::class, IOException::class)
    fun test_TSIG_truncated() {
        val key = TSIG(HMAC_SHA256, "example.", "12345678")
        val qname = fromString("www.example.")
        val question = newRecord(qname, DnsRecordType.A, DnsClass.IN, 0L)
        val query = newQuery(question)
        query.setTSIG(key, DnsResponseCode.NOERROR, null)
        val qbytes = query.toWire()
        val qparsed = DnsMessage(qbytes)
        val response = DnsMessage(
            query.header.iD
        )
        response.setTSIG(key, DnsResponseCode.NOERROR, qparsed.tSIG)
        response.header.setFlag(Flags.QR)
        response.addRecord(question, DnsSection.QUESTION)
        for (i in 0..39) {
            val answer = fromString(qname, DnsRecordType.TXT, DnsClass.IN, 300, "foo$i", null)
            response.addRecord(answer, DnsSection.ANSWER)
        }
        val bytes = response.toWire(512)
        val parsed = DnsMessage(bytes)
        assertTrue(
            parsed.header.getFlag(Flags.TC)
        )
        val result = key.verify(parsed, bytes, qparsed.tSIG)
        assertEquals(result, DnsResponseCode.NOERROR)
        assertTrue(parsed.isSigned)
    }
}
