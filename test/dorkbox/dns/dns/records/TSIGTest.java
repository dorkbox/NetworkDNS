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

import java.io.IOException;

import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsClass;
import dorkbox.dns.dns.constants.DnsRecordType;
import dorkbox.dns.dns.constants.DnsResponseCode;
import dorkbox.dns.dns.constants.DnsSection;
import dorkbox.dns.dns.constants.Flags;
import dorkbox.dns.dns.exceptions.TextParseException;
import dorkbox.dns.dns.records.DnsMessage;
import dorkbox.dns.dns.records.DnsRecord;
import dorkbox.dns.dns.records.TSIG;
import junit.framework.TestCase;

public
class TSIGTest extends TestCase {
    public
    void test_TSIG_query() throws TextParseException, IOException {
        TSIG key = new TSIG(TSIG.HMAC_SHA256, "example.", "12345678");

        Name qname = Name.fromString("www.example.");
        DnsRecord rec = DnsRecord.newRecord(qname, DnsRecordType.A, DnsClass.IN);
        DnsMessage msg = DnsMessage.newQuery(rec);
        msg.setTSIG(key, DnsResponseCode.NOERROR, null);
        byte[] bytes = msg.toWire(512);
        assertEquals(bytes[11], 1);

        DnsMessage parsed = new DnsMessage(bytes);
        int result = key.verify(parsed, bytes, null);
        assertEquals(result, DnsResponseCode.NOERROR);
        assertTrue(parsed.isSigned());
    }

    public
    void test_TSIG_response() throws TextParseException, IOException {
        TSIG key = new TSIG(TSIG.HMAC_SHA256, "example.", "12345678");

        Name qname = Name.fromString("www.example.");
        DnsRecord question = DnsRecord.newRecord(qname, DnsRecordType.A, DnsClass.IN);
        DnsMessage query = DnsMessage.newQuery(question);
        query.setTSIG(key, DnsResponseCode.NOERROR, null);
        byte[] qbytes = query.toWire();
        DnsMessage qparsed = new DnsMessage(qbytes);

        DnsMessage response = new DnsMessage(query.getHeader()
                                                  .getID());
        response.setTSIG(key, DnsResponseCode.NOERROR, qparsed.getTSIG());
        response.getHeader()
                .setFlag(Flags.QR);
        response.addRecord(question, DnsSection.QUESTION);
        DnsRecord answer = DnsRecord.fromString(qname, DnsRecordType.A, DnsClass.IN, 300, "1.2.3.4", null);
        response.addRecord(answer, DnsSection.ANSWER);
        byte[] bytes = response.toWire(512);

        DnsMessage parsed = new DnsMessage(bytes);
        int result = key.verify(parsed, bytes, qparsed.getTSIG());
        assertEquals(result, DnsResponseCode.NOERROR);
        assertTrue(parsed.isSigned());
    }

    public
    void test_TSIG_truncated() throws TextParseException, IOException {
        TSIG key = new TSIG(TSIG.HMAC_SHA256, "example.", "12345678");

        Name qname = Name.fromString("www.example.");
        DnsRecord question = DnsRecord.newRecord(qname, DnsRecordType.A, DnsClass.IN);
        DnsMessage query = DnsMessage.newQuery(question);
        query.setTSIG(key, DnsResponseCode.NOERROR, null);
        byte[] qbytes = query.toWire();
        DnsMessage qparsed = new DnsMessage(qbytes);

        DnsMessage response = new DnsMessage(query.getHeader()
                                                  .getID());
        response.setTSIG(key, DnsResponseCode.NOERROR, qparsed.getTSIG());
        response.getHeader()
                .setFlag(Flags.QR);
        response.addRecord(question, DnsSection.QUESTION);
        for (int i = 0; i < 40; i++) {
            DnsRecord answer = DnsRecord.fromString(qname, DnsRecordType.TXT, DnsClass.IN, 300, "foo" + i, null);
            response.addRecord(answer, DnsSection.ANSWER);
        }
        byte[] bytes = response.toWire(512);

        DnsMessage parsed = new DnsMessage(bytes);
        assertTrue(parsed.getHeader()
                         .getFlag(Flags.TC));
        int result = key.verify(parsed, bytes, qparsed.getTSIG());
        assertEquals(result, DnsResponseCode.NOERROR);
        assertTrue(parsed.isSigned());
    }
}
