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

import org.junit.Test;

import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsClass;
import dorkbox.dns.dns.exceptions.TextParseException;
import dorkbox.dns.dns.server.Response;
import dorkbox.dns.dns.zone.AbstractZone;
import dorkbox.dns.dns.zone.ZoneDatabase;
import dorkbox.dns.dns.zone.ZoneType;
import junit.framework.TestCase;

public
class ZoneDatabaseTest extends TestCase {

    class TestZone extends AbstractZone {
        public
        TestZone(String name) throws TextParseException {
            super(ZoneType.master, Name.fromString(name));
        }

        @Override
        public
        Response find(final Name qname, final int recordType) {
            return null;
        }
    }

    @Test
    public
    void testFind() throws TextParseException {
        ZoneDatabase db = new ZoneDatabase();
        db.add(new TestZone("example.com."));
        db.add(new TestZone("example.co.jp."));
        db.add(new TestZone("jp."));
        db.add(new TestZone("ne.jp."));

        assertNotNull(db.prepare(Name.fromString("jp."), DnsClass.IN));
        assertNull(db.prepare(Name.fromString("com."), DnsClass.IN));
    }
}
