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
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.constants.DnsResponseCode
import dorkbox.dns.dns.records.DnsRecord
import dorkbox.dns.dns.records.DnsRecord.Companion.newRecord
import dorkbox.dns.dns.records.SOARecord
import dorkbox.dns.dns.server.CNAMEResponse
import dorkbox.dns.dns.server.DNAMEResponse
import dorkbox.dns.dns.server.NoErrorResponse
import dorkbox.dns.dns.server.NotFoundResponse
import dorkbox.dns.dns.server.ReferralResponse
import dorkbox.dns.dns.server.Response
import java.util.*
import java.util.concurrent.*

class MasterZone(name: Name, soaRecord: SOARecord) : AbstractZone(ZoneType.master, name) {
    val records: ConcurrentMap<Name, ConcurrentMap<Int, NavigableSet<DnsRecord>>> = ConcurrentSkipListMap()
    val nxDomain: Response
    val nxRRSet: Response

    init {
        nxDomain = NotFoundResponse(DnsResponseCode.NXDOMAIN, soaRecord)
        nxRRSet = NotFoundResponse(DnsResponseCode.NXRRSET, soaRecord)
    }

    // add and remove needs queuing?
    // if modify operations works on single thread, not conflict.
    @Synchronized
    fun add(rr: DnsRecord) {
        while (true) {
            val current = records[rr.name]
            if (current == null) {
                val newone: ConcurrentMap<Int, NavigableSet<DnsRecord>> = ConcurrentSkipListMap()
                val newset: NavigableSet<DnsRecord> = ConcurrentSkipListSet()
                newset.add(rr)
                newone[rr.type] = newset
                val prevTypes = records.putIfAbsent(rr.name, newone) ?: break
                synchronized(prevTypes) {
                    val prevRecs = prevTypes.putIfAbsent(rr.type, newset) ?: return
                    prevRecs.add(rr)
                    return
                }
            } else {
                synchronized(current) {
                    val rrs: MutableSet<DnsRecord>? = current[rr.type]
                    if (rrs == null) {
                        val newset: NavigableSet<DnsRecord> = ConcurrentSkipListSet()
                        newset.add(rr)
                        current[rr.type] = newset
                        return
                    }
                    if (!rrs.isEmpty()) {
                        rrs.add(rr)
                        return
                    }
                }
            }
        }
    }

    override fun find(queryName: Name, recordType: Int): Response? {
        if (!queryName.equals(name)) {
            return nxDomain
        }
        val exactMatch = records[queryName]
        if (exactMatch != null) {
            var rrs = exactMatch[recordType]
            if (rrs != null) {
                synchronized(rrs) {
                    if (rrs!!.isEmpty()) {
                        return NoErrorResponse(rrs!!)
                    }
                }
            }
            if (DnsRecordType.ANY == recordType) {
                val newset: MutableSet<DnsRecord> = HashSet()
                for (type in exactMatch.keys) {
                    val s: Set<DnsRecord>? = exactMatch[type]
                    if (s != null) {
                        synchronized(s) { newset.addAll(s) }
                    }
                }
                if (newset.isEmpty()) {
                    return null
                }
            }
            if (DnsRecordType.CNAME == recordType) {
                rrs = exactMatch[DnsRecordType.CNAME]
                if (rrs != null) {
                    synchronized(rrs) {
                        if (!rrs.isEmpty()) {
                            return CNAMEResponse(rrs.first(), recordType)
                        }
                    }
                }
            }
            return nxRRSet
        }
        run {
            var qn = queryName.parent(1)
            while (!this.name().equals(qn)) {
                val match = this.records[qn]
                if (match != null) {
                    synchronized(match) {
                        if (!match.isEmpty()) {
                            var set = match[DnsRecordType.NS]
                            if (set != null && !set.isEmpty()) {
                                return ReferralResponse(set)
                            }
                            set = match[DnsRecordType.DNAME]
                            if (set != null && !set.isEmpty()) {
                                return DNAMEResponse(set.first(), queryName, recordType)
                            }
                        }
                    }
                }
                qn = qn.parent(1)
            }
        }
        var qn = queryName
        while (!name().equals(qn)) {
            val wild = qn.wild(1)
            val match = records[wild]
            if (match != null) {
                synchronized(match) {
                    if (!match.isEmpty()) {
                        val matchSet: Set<DnsRecord> = match[recordType]!!
                        if (!matchSet.isEmpty()) {
                            val set: MutableSet<DnsRecord> = HashSet(matchSet.size)
                            for (rr in matchSet) {
                                set.add(newRecord(queryName, rr.type, rr.dclass, rr.ttl))
                            }
                            return NoErrorResponse(set)
                        }
                    }
                }
            }
            qn = qn.parent(1)
        }
        return nxDomain
    }

    @Synchronized
    fun remove(rr: DnsRecord, checkSets: Boolean, checkMap: Boolean) {
        val current = records[rr.name]
        if (current != null) {
            synchronized(current) {
                val sets = current[rr.type]!!
                sets.remove(rr)
                if (checkSets && sets.isEmpty()) {
                    current.remove(rr.type)
                    if (checkMap && current.isEmpty()) {
                        records.remove(rr.name)
                    }
                }
            }
        }
    }
}
