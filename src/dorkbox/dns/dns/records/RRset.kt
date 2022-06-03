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
package dorkbox.dns.dns.records

import dorkbox.dns.dns.Name
import dorkbox.dns.dns.constants.DnsClass
import dorkbox.dns.dns.constants.DnsRecordType
import java.io.Serializable
import java.util.*

/**
 * A set of Records with the same name, type, and class.  Also included
 * are all RRSIG records signing the data records.
 *
 * @author Brian Wellington
 * @see DnsRecord
 *
 * @see RRSIGRecord
 */
class RRset : Serializable {
    /*
     * rrs contains both normal and RRSIG records, with the RRSIG records
     * at the end.
     */
    private var resourceRecords: MutableList<DnsRecord> = ArrayList(1)
    private var nsigs: Short = 0
    private var position: Short = 0

    /**
     * Creates an RRset and sets its contents to the specified record
     */
    constructor(record: DnsRecord) : this() {
        safeAddRR(record)
    }

    /**
     * Creates an empty RRset
     */
    constructor()

    private fun safeAddRR(r: DnsRecord) {
        if (r !is RRSIGRecord) {
            if (nsigs.toInt() == 0) {
                resourceRecords.add(r)
            } else {
                resourceRecords.add(resourceRecords.size - nsigs, r)
            }
        } else {
            resourceRecords.add(r)
            nsigs++
        }
    }

    /**
     * Creates an RRset with the contents of an existing RRset
     */
    constructor(rrset: RRset) {
        synchronized(rrset) {

            resourceRecords = ArrayList(rrset.resourceRecords)
            nsigs = rrset.nsigs
            position = rrset.position
        }
    }

    /**
     * Adds a Record to an RRset
     */
    @Synchronized
    fun addRR(r: DnsRecord) {
        var r = r
        if (resourceRecords.size == 0) {
            safeAddRR(r)
            return
        }
        val first = first()
        require(r.sameRRset(first)) { "record does not match " + "rrset" }
        if (r.ttl != first.ttl) {
            if (r.ttl > first.ttl) {
                r = r.cloneRecord()
                r.ttl = first.ttl
            } else {
                for (i in resourceRecords.indices) {
                    var tmp = resourceRecords[i]
                    tmp = tmp.cloneRecord()
                    tmp.ttl = r.ttl
                    resourceRecords[i] = tmp
                }
            }
        }
        if (!resourceRecords.contains(r)) {
            safeAddRR(r)
        }
    }

    /**
     * Returns the first record
     *
     * @throws IllegalStateException if the rrset is empty
     */
    @Synchronized
    fun first(): DnsRecord {
        check(resourceRecords.size != 0) { "rrset is empty" }
        return resourceRecords[0]
    }

    /**
     * Deletes a Record from an RRset
     */
    @Synchronized
    fun deleteRR(r: DnsRecord) {
        if (resourceRecords.remove(r) && r is RRSIGRecord) {
            nsigs--
        }
    }

    /**
     * Deletes all Records from an RRset
     */
    @Synchronized
    fun clear() {
        resourceRecords.clear()
        position = 0
        nsigs = 0
    }

    /**
     * Returns an Iterator listing all (data) records.
     *
     * @param cycle If true, cycle through the records so that each Iterator will
     * start with a different record.
     */
    @Synchronized
    fun rrs(cycle: Boolean): Iterator<*> {
        return iterator(true, cycle)
    }

    @Synchronized
    private fun iterator(data: Boolean, cycle: Boolean): Iterator<*> {
        val size: Int
        val start: Int
        val total: Int
        total = resourceRecords.size
        size = if (data) {
            total - nsigs
        } else {
            nsigs.toInt()
        }
        if (size == 0) {
            return Collections.EMPTY_LIST.iterator()
        }
        if (data) {
            if (!cycle) {
                start = 0
            } else {
                if (position >= size) {
                    position = 0
                }
                start = position++.toInt()
            }
        } else {
            start = total - nsigs
        }
        val list: MutableList<DnsRecord> = ArrayList(size)
        if (data) {
            list.addAll(resourceRecords.subList(start, size))
            if (start != 0) {
                list.addAll(resourceRecords.subList(0, start))
            }
        } else {
            list.addAll(resourceRecords.subList(start, total))
        }
        return list.iterator()
    }

    /**
     * Returns an Iterator listing all (data) records.  This cycles through
     * the records, so each Iterator will start with a different record.
     */
    @Synchronized
    fun rrs(): Iterator<*> {
        return iterator(true, true)
    }

    /**
     * Returns an Iterator listing all signature records
     */
    @Synchronized
    fun sigs(): Iterator<*> {
        return iterator(false, false)
    }

    /**
     * Returns the number of (data) records
     */
    @Synchronized
    fun size(): Int {
        return resourceRecords.size - nsigs
    }

    /**
     * Converts the RRset to a String
     */
    override fun toString(): String {
        if (resourceRecords!!.size == 0) {
            return "{empty}"
        }
        val sb = StringBuilder()
        sb.append("{ ")
        sb.append("$name ")
        sb.append("$TTL ")
        sb.append(DnsClass.string(dClass) + " ")
        sb.append(DnsRecordType.string(this.type) + " ")
        sb.append(iteratorToString(iterator(true, false)))
        if (nsigs > 0) {
            sb.append(" sigs: ")
            sb.append(iteratorToString(iterator(false, false)))
        }
        sb.append(" }")
        return sb.toString()
    }

    /**
     * Returns the name of the records
     *
     * @see Name
     */
    val name: Name
        get() = first().name

    /**
     * Returns the type of the records
     *
     * @see DnsRecordType
     */
    val type: Int
        get() = first().rRsetType

    /**
     * Returns the class of the records
     *
     * @see DnsClass
     */
    val dClass: Int
        get() = first().dclass

    /**
     * Returns the ttl of the records
     */
    @get:Synchronized
    val TTL: Long
        get() = first().ttl

    private fun iteratorToString(it: Iterator<*>): String {
        val sb = StringBuilder()
        while (it.hasNext()) {
            val rr = it.next() as DnsRecord
            sb.append("[")
            rr.rdataToString(sb)
            sb.append("]")
            if (it.hasNext()) {
                sb.append(" ")
            }
        }
        return sb.toString()
    }

    companion object {
        private const val serialVersionUID = -3270249290171239695L
    }
}
