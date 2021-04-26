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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Date;
import java.util.Iterator;

import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsClass;
import dorkbox.dns.dns.constants.DnsRecordType;
import dorkbox.dns.dns.exceptions.TextParseException;
import dorkbox.dns.dns.records.ARecord;
import dorkbox.dns.dns.records.CNAMERecord;
import dorkbox.dns.dns.records.DnsRecord;
import dorkbox.dns.dns.records.RRSIGRecord;
import dorkbox.dns.dns.records.RRset;
import junit.framework.TestCase;

public
class RRsetTest extends TestCase {
    private RRset m_rs;
    Name m_name, m_name2;
    long m_ttl;
    ARecord m_a1, m_a2;
    RRSIGRecord m_s1, m_s2;

    @Override
    public
    void setUp() throws TextParseException, UnknownHostException {
        m_rs = new RRset();
        m_name = Name.fromString("this.is.a.test.");
        m_name2 = Name.fromString("this.is.another.test.");
        m_ttl = 0xABCDL;
        m_a1 = new ARecord(m_name, DnsClass.IN, m_ttl, InetAddress.getByName("192.169.232.11"));
        m_a2 = new ARecord(m_name, DnsClass.IN, m_ttl + 1, InetAddress.getByName("192.169.232.12"));

        m_s1 = new RRSIGRecord(m_name,
                               DnsClass.IN,
                               m_ttl,
                               DnsRecordType.A,
                               0xF,
                               0xABCDEL,
                               new Date(),
                               new Date(),
                               0xA,
                               m_name,
                               new byte[0]);
        m_s2 = new RRSIGRecord(m_name,
                               DnsClass.IN,
                               m_ttl,
                               DnsRecordType.A,
                               0xF,
                               0xABCDEL,
                               new Date(),
                               new Date(),
                               0xA,
                               m_name2,
                               new byte[0]);
    }

    public
    void test_ctor_0arg() {
        assertEquals(0, m_rs.size());
        try {
            m_rs.getDClass();
            fail("IllegalStateException not thrown");
        } catch (IllegalStateException e) {
        }
        try {
            m_rs.getType();
            fail("IllegalStateException not thrown");
        } catch (IllegalStateException e) {
        }
        try {
            m_rs.getTTL();
            fail("IllegalStateException not thrown");
        } catch (IllegalStateException e) {
        }
        try {
            m_rs.getName();
            fail("IllegalStateException not thrown");
        } catch (IllegalStateException e) {
        }
        try {
            m_rs.first();
            fail("IllegalStateException not thrown");
        } catch (IllegalStateException e) {
        }

        assertEquals("{empty}", m_rs.toString());

        Iterator itr = m_rs.rrs();
        assertNotNull(itr);
        assertFalse(itr.hasNext());

        itr = m_rs.sigs();
        assertNotNull(itr);
        assertFalse(itr.hasNext());
    }

    public
    void test_basics() throws TextParseException, UnknownHostException {
        m_rs.addRR(m_a1);

        assertEquals(1, m_rs.size());
        assertEquals(DnsClass.IN, m_rs.getDClass());
        assertEquals(m_a1, m_rs.first());
        assertEquals(m_name, m_rs.getName());
        assertEquals(m_ttl, m_rs.getTTL());
        assertEquals(DnsRecordType.A, m_rs.getType());

        // add it again, and make sure nothing changed
        m_rs.addRR(m_a1);

        assertEquals(1, m_rs.size());
        assertEquals(DnsClass.IN, m_rs.getDClass());
        assertEquals(m_a1, m_rs.first());
        assertEquals(m_name, m_rs.getName());
        assertEquals(m_ttl, m_rs.getTTL());
        assertEquals(DnsRecordType.A, m_rs.getType());

        m_rs.addRR(m_a2);

        assertEquals(2, m_rs.size());
        assertEquals(DnsClass.IN, m_rs.getDClass());
        DnsRecord r = m_rs.first();
        assertEquals(m_a1, r);
        assertEquals(m_name, m_rs.getName());
        assertEquals(m_ttl, m_rs.getTTL());
        assertEquals(DnsRecordType.A, m_rs.getType());

        Iterator itr = m_rs.rrs();
        assertEquals(m_a1, itr.next());
        assertEquals(m_a2, itr.next());

        // make sure that it rotates
        itr = m_rs.rrs();
        assertEquals(m_a2, itr.next());
        assertEquals(m_a1, itr.next());
        itr = m_rs.rrs();
        assertEquals(m_a1, itr.next());
        assertEquals(m_a2, itr.next());

        m_rs.deleteRR(m_a1);
        assertEquals(1, m_rs.size());
        assertEquals(DnsClass.IN, m_rs.getDClass());
        assertEquals(m_a2, m_rs.first());
        assertEquals(m_name, m_rs.getName());
        assertEquals(m_ttl, m_rs.getTTL());
        assertEquals(DnsRecordType.A, m_rs.getType());

        // the signature records
        m_rs.addRR(m_s1);
        assertEquals(1, m_rs.size());
        itr = m_rs.sigs();
        assertEquals(m_s1, itr.next());
        assertFalse(itr.hasNext());

        m_rs.addRR(m_s1);
        itr = m_rs.sigs();
        assertEquals(m_s1, itr.next());
        assertFalse(itr.hasNext());

        m_rs.addRR(m_s2);
        itr = m_rs.sigs();
        assertEquals(m_s1, itr.next());
        assertEquals(m_s2, itr.next());
        assertFalse(itr.hasNext());

        m_rs.deleteRR(m_s1);
        itr = m_rs.sigs();
        assertEquals(m_s2, itr.next());
        assertFalse(itr.hasNext());


        // clear it all
        m_rs.clear();
        assertEquals(0, m_rs.size());
        assertFalse(m_rs.rrs()
                        .hasNext());
        assertFalse(m_rs.sigs()
                        .hasNext());

    }

    public
    void test_ctor_1arg() {
        m_rs.addRR(m_a1);
        m_rs.addRR(m_a2);
        m_rs.addRR(m_s1);
        m_rs.addRR(m_s2);

        RRset rs2 = new RRset(m_rs);

        assertEquals(2, rs2.size());
        assertEquals(m_a1, rs2.first());
        Iterator itr = rs2.rrs();
        assertEquals(m_a1, itr.next());
        assertEquals(m_a2, itr.next());
        assertFalse(itr.hasNext());

        itr = rs2.sigs();
        assertTrue(itr.hasNext());
        assertEquals(m_s1, itr.next());
        assertTrue(itr.hasNext());
        assertEquals(m_s2, itr.next());
        assertFalse(itr.hasNext());
    }

    public
    void test_toString() {
        m_rs.addRR(m_a1);
        m_rs.addRR(m_a2);
        m_rs.addRR(m_s1);
        m_rs.addRR(m_s2);

        String out = m_rs.toString();

        assertTrue(out.indexOf(m_name.toString()) != -1);
        assertTrue(out.indexOf(" IN A ") != -1);
        assertTrue(out.indexOf("[192.169.232.11]") != -1);
        assertTrue(out.indexOf("[192.169.232.12]") != -1);
    }

    public
    void test_addRR_invalidType() throws TextParseException {
        m_rs.addRR(m_a1);

        CNAMERecord c = new CNAMERecord(m_name, DnsClass.IN, m_ttl, Name.fromString("an.alias."));

        try {
            m_rs.addRR(c);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    public
    void test_addRR_invalidName() throws TextParseException, UnknownHostException {
        m_rs.addRR(m_a1);

        m_a2 = new ARecord(m_name2, DnsClass.IN, m_ttl, InetAddress.getByName("192.169.232.11"));

        try {
            m_rs.addRR(m_a2);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    public
    void test_addRR_invalidDClass() throws TextParseException, UnknownHostException {
        m_rs.addRR(m_a1);

        m_a2 = new ARecord(m_name, DnsClass.CHAOS, m_ttl, InetAddress.getByName("192.169.232.11"));

        try {
            m_rs.addRR(m_a2);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
    }

    public
    void test_TTLcalculation() {
        m_rs.addRR(m_a2);
        assertEquals(m_a2.getTTL(), m_rs.getTTL());
        m_rs.addRR(m_a1);
        assertEquals(m_a1.getTTL(), m_rs.getTTL());

        Iterator itr = m_rs.rrs();
        while (itr.hasNext()) {
            DnsRecord r = (DnsRecord) itr.next();
            assertEquals(m_a1.getTTL(), r.getTTL());
        }
    }

    public
    void test_Record_placement() {
        m_rs.addRR(m_a1);
        m_rs.addRR(m_s1);
        m_rs.addRR(m_a2);

        Iterator itr = m_rs.rrs();
        assertTrue(itr.hasNext());
        assertEquals(m_a1, itr.next());
        assertTrue(itr.hasNext());
        assertEquals(m_a2, itr.next());
        assertFalse(itr.hasNext());

        itr = m_rs.sigs();
        assertTrue(itr.hasNext());
        assertEquals(m_s1, itr.next());
        assertFalse(itr.hasNext());
    }

    public
    void test_noncycling_iterator() {
        m_rs.addRR(m_a1);
        m_rs.addRR(m_a2);

        Iterator itr = m_rs.rrs(false);
        assertTrue(itr.hasNext());
        assertEquals(m_a1, itr.next());
        assertTrue(itr.hasNext());
        assertEquals(m_a2, itr.next());

        itr = m_rs.rrs(false);
        assertTrue(itr.hasNext());
        assertEquals(m_a1, itr.next());
        assertTrue(itr.hasNext());
        assertEquals(m_a2, itr.next());
    }
}
