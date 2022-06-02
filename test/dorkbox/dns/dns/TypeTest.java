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
package dorkbox.dns.dns;

import dorkbox.dns.dns.constants.DnsRecordType;
import junit.framework.TestCase;

public
class TypeTest extends TestCase {
    public
    void test_string() {
        // a regular one
        assertEquals("CNAME", DnsRecordType.INSTANCE.string(DnsRecordType.CNAME));

        // one that doesn't exist
        assertTrue(DnsRecordType.INSTANCE.string(65535)
                                .startsWith("TYPE"));

        try {
            DnsRecordType.INSTANCE.string(-1);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    public
    void test_value() {
        // regular one
        assertEquals(DnsRecordType.MAILB, DnsRecordType.INSTANCE.value("MAILB"));

        // one thats undefined but within range
        assertEquals(300, DnsRecordType.INSTANCE.value("TYPE300"));

        // something that unknown
        assertEquals(-1, DnsRecordType.INSTANCE.value("THIS IS DEFINITELY UNKNOWN"));

        // empty string
        assertEquals(-1, DnsRecordType.INSTANCE.value(""));
    }

    public
    void test_value_2arg() {
        assertEquals(301, DnsRecordType.INSTANCE.value("301", true));
    }

    public
    void test_isRR() {
        assertTrue(DnsRecordType.INSTANCE.isRR(DnsRecordType.CNAME));
        assertFalse(DnsRecordType.INSTANCE.isRR(DnsRecordType.IXFR));
    }
}
