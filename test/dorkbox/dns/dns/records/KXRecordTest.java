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
import junit.framework.TestCase;

public
class KXRecordTest extends TestCase {
    public
    void test_getObject() {
        KXRecord d = new KXRecord();
        DnsRecord r = d.getObject();
        assertTrue(r instanceof KXRecord);
    }

    public
    void test_ctor_5arg() throws TextParseException {
        Name n = Name.Companion.fromString("My.Name.");
        Name m = Name.Companion.fromString("My.OtherName.");

        KXRecord d = new KXRecord(n, DnsClass.IN, 0xABCDEL, 0xF1, m);
        assertEquals(n, d.getName());
        assertEquals(DnsRecordType.KX, d.getType());
        assertEquals(DnsClass.IN, d.getDclass());
        assertEquals(0xABCDEL, d.getTtl());
        assertEquals(0xF1, d.getPreference());
        assertEquals(m, d.getTarget());
        assertEquals(m, d.getAdditionalName());
    }
}
