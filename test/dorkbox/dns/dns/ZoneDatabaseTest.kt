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
package dorkbox.dns.dns

import dorkbox.dns.dns.Name.Companion.fromString
import dorkbox.dns.dns.constants.DnsClass
import dorkbox.dns.dns.exceptions.TextParseException
import dorkbox.dns.dns.server.Response
import dorkbox.dns.dns.zone.AbstractZone
import dorkbox.dns.dns.zone.ZoneDatabase
import dorkbox.dns.dns.zone.ZoneType
import junit.framework.TestCase
import org.junit.Test

class ZoneDatabaseTest : TestCase() {
    internal inner class TestZone(name: String) : AbstractZone(ZoneType.master, fromString(name)) {
        override fun find(qname: Name, recordType: Int): Response? {
            return null
        }
    }

    @Test
    @Throws(TextParseException::class)
    fun testFind() {
        val db = ZoneDatabase()
        db.add(TestZone("example.com."))
        db.add(TestZone("example.co.jp."))
        db.add(TestZone("jp."))
        db.add(TestZone("ne.jp."))
        assertNotNull(db.prepare(fromString("jp."), DnsClass.IN))
        assertNull(db.prepare(fromString("com."), DnsClass.IN))
    }
}
