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
import java.net.UnknownHostException;

import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.records.DnsRecord;
import dorkbox.dns.dns.records.EmptyRecord;
import dorkbox.dns.dns.utils.Tokenizer;
import junit.framework.TestCase;

public
class EmptyRecordTest extends TestCase {
    public
    void test_ctor() throws UnknownHostException {
        EmptyRecord ar = new EmptyRecord();
        assertNull(ar.getName());
        assertEquals(0, ar.getType());
        assertEquals(0, ar.getDClass());
        assertEquals(0, ar.getTTL());
    }

    public
    void test_getObject() {
        EmptyRecord ar = new EmptyRecord();
        DnsRecord r = ar.getObject();
        assertTrue(r instanceof EmptyRecord);
    }

    public
    void test_rrFromWire() throws IOException {
        DnsInput i = new DnsInput(new byte[] {1, 2, 3, 4, 5});
        i.jump(3);

        EmptyRecord er = new EmptyRecord();
        er.rrFromWire(i);
        assertEquals(3, i.readIndex());
        assertNull(er.getName());
        assertEquals(0, er.getType());
        assertEquals(0, er.getDClass());
        assertEquals(0, er.getTTL());
    }

    public
    void test_rdataFromString() throws IOException {
        Tokenizer t = new Tokenizer("these are the tokens");
        EmptyRecord er = new EmptyRecord();
        er.rdataFromString(t, null);
        assertNull(er.getName());
        assertEquals(0, er.getType());
        assertEquals(0, er.getDClass());
        assertEquals(0, er.getTTL());

        assertEquals("these", t.getString());
    }

    public
    void test_rrToString() {
        EmptyRecord er = new EmptyRecord();
        StringBuilder sb = new StringBuilder();
        er.rrToString(sb);
        assertEquals("", sb.toString());
    }

    public
    void test_rrToWire() {
        EmptyRecord er = new EmptyRecord();
        DnsOutput out = new DnsOutput();
        er.rrToWire(out, null, true);
        assertEquals(0, out.toByteArray().length);
    }
}
