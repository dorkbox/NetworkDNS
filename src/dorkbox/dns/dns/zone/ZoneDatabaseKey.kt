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
import dorkbox.dns.dns.records.DnsRecord

/**
 *
 */
class ZoneDatabaseKey(var name: Name, var dnsclass: Int) : Comparable<ZoneDatabaseKey> {
    constructor(z: Zone) : this(z.name(), z.dnsClass()) {}
    constructor(rr: DnsRecord) : this(rr.name, rr.dclass) {}

    override fun compareTo(o: ZoneDatabaseKey): Int {
        if (o == null) {
            return 1
        }
        return if (equals(o)) {
            0
        } else this.hashCode() - o.hashCode()
    }

    fun equals(other: ZoneDatabaseKey): Boolean {
        return dnsclass == other.dnsclass && name.equals(other.name)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other == null) {
            return false
        }
        return if (javaClass != other.javaClass) {
            false
        } else equals(other as ZoneDatabaseKey)
    }

    override fun hashCode(): Int {
        val prime = 31
        var result = 1
        result = prime * result + dnsclass
        result = prime * result + name.hashCode()
        return result
    }

    fun name(): Name {
        return name
    }

    fun name(name: Name) {
        this.name = name
    }
}
