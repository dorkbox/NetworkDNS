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

import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsClass;
import dorkbox.dns.dns.constants.DnsRecordType;
import dorkbox.dns.dns.exceptions.TextParseException;
import dorkbox.dns.dns.records.DnsRecord;
import dorkbox.dns.dns.records.MGRecord;
import junit.framework.TestCase;

public
class MGRecordTest extends TestCase {
    public
    void test_ctor_0arg() {
        MGRecord d = new MGRecord();
        assertNull(d.getName());
        assertNull(d.getMailbox());
    }

    public
    void test_ctor_4arg() throws TextParseException {
        Name n = Name.fromString("my.name.");
        Name a = Name.fromString("my.alias.");

        MGRecord d = new MGRecord(n, DnsClass.IN, 0xABCDEL, a);
        assertEquals(n, d.getName());
        assertEquals(DnsRecordType.MG, d.getType());
        assertEquals(DnsClass.IN, d.getDClass());
        assertEquals(0xABCDEL, d.getTTL());
        assertEquals(a, d.getMailbox());
    }

    public
    void test_getObject() {
        MGRecord d = new MGRecord();
        DnsRecord r = d.getObject();
        assertTrue(r instanceof MGRecord);
    }
}
