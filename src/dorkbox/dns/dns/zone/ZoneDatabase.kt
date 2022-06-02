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
package dorkbox.dns.dns.zone

import dorkbox.dns.dns.Name
import java.util.concurrent.*

class ZoneDatabase {
    var zones: MutableMap<ZoneDatabaseKey, Zone> = ConcurrentSkipListMap()

    fun add(zone: Zone /* TODO ZoneConfig? */) {
        zones[ZoneDatabaseKey(zone)] = zone
    }

    fun prepare(name: Name, dnsClass: Int): Query? {
        val zk = ZoneDatabaseKey(name, dnsClass)
        var found = zones[zk]
        if (found != null) {
            // exact match
            return Query(name, name, dnsClass, found, this)
        }
        var child = name
        // partial match
        var i = 0
        val size = zones.size
        while (i < size) {
            val p = child.parent(1)
            zk.name(p)
            found = zones[zk]
            child = if (found == null) {
                if (p.labels() <= 1) {
                    break
                }
                p
            } else {
                return Query(name, p, dnsClass, found, this)
            }
            i++
        }

        // not found.
        return null
    }
}
