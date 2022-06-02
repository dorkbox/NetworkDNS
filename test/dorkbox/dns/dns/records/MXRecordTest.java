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

import java.util.Arrays;

import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsClass;
import dorkbox.dns.dns.constants.DnsRecordType;
import dorkbox.dns.dns.exceptions.TextParseException;
import junit.framework.TestCase;

public
class MXRecordTest extends TestCase {
    public
    void test_getObject() {
        MXRecord d = new MXRecord();
        DnsRecord r = d.getObject();
        assertTrue(r instanceof MXRecord);
    }

    public
    void test_ctor_5arg() throws TextParseException {
        Name n = Name.Companion.fromString("My.Name.");
        Name m = Name.Companion.fromString("My.OtherName.");

        MXRecord d = new MXRecord(n, DnsClass.IN, 0xABCDEL, 0xF1, m);
        assertEquals(n, d.getName());
        assertEquals(DnsRecordType.MX, d.getType());
        assertEquals(DnsClass.IN, d.getDclass());
        assertEquals(0xABCDEL, d.getTtl());
        assertEquals(0xF1, d.getPriority());
        assertEquals(m, d.getTarget());
        assertEquals(m, d.getAdditionalName());
    }

    public
    void test_rrToWire() throws TextParseException {
        Name n = Name.Companion.fromString("My.Name.");
        Name m = Name.Companion.fromString("M.O.n.");

        MXRecord mr = new MXRecord(n, DnsClass.IN, 0xB12FL, 0x1F2B, m);

        // canonical
        DnsOutput dout = new DnsOutput();
        mr.rrToWire(dout, null, true);
        byte[] out = dout.toByteArray();
        byte[] exp = new byte[] {0x1F, 0x2B, 1, 'm', 1, 'o', 1, 'n', 0};
        assertTrue(Arrays.equals(exp, out));

        // case sensitive
        dout = new DnsOutput();
        mr.rrToWire(dout, null, false);
        out = dout.toByteArray();
        exp = new byte[] {0x1F, 0x2B, 1, 'M', 1, 'O', 1, 'n', 0};
        assertTrue(Arrays.equals(exp, out));
    }
}
