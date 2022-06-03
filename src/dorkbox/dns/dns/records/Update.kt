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
import dorkbox.dns.dns.constants.DnsClass.check
import dorkbox.dns.dns.constants.DnsOpCode
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.constants.DnsSection
import dorkbox.dns.dns.exceptions.RelativeNameException
import dorkbox.dns.dns.utils.Tokenizer
import java.io.IOException

/**
 * A helper class for constructing dynamic DNS (DDNS) update messages.
 *
 * @author Brian Wellington
 */
class Update(zone: Name, dclass: Int = DnsClass.IN) : DnsMessage() {
    private val origin: Name
    private val dclass: Int
    /**
     * Creates an update message.
     *
     * @param zone The name of the zone being updated.
     * @param dclass The class of the zone being updated.
     */
    init {
        if (!zone.isAbsolute) {
            throw RelativeNameException(zone)
        }
        origin = zone

        check(dclass)
        this.dclass = dclass

        header.opcode = DnsOpCode.UPDATE

        val soa = DnsRecord.newRecord(zone, DnsRecordType.SOA, DnsClass.IN)
        addRecord(soa, DnsSection.QUESTION)

    }

    /**
     * Inserts a prerequisite that the specified name exists; that is, there
     * exist records with the given name in the zone.
     */
    fun present(name: Name) {
        newPrereq(DnsRecord.newRecord(name, DnsRecordType.ANY, DnsClass.ANY, 0))
    }

    private fun newPrereq(rec: DnsRecord) {
        addRecord(rec, DnsSection.PREREQ)
    }

    /**
     * Inserts a prerequisite that the specified rrset exists; that is, there
     * exist records with the given name and type in the zone.
     */
    fun present(name: Name, type: Int) {
        newPrereq(DnsRecord.newRecord(name, type, DnsClass.ANY, 0))
    }

    /**
     * Parses a record from the string, and inserts a prerequisite that the
     * record exists.  Due to the way value-dependent prequisites work, the
     * condition that must be met is that the set of all records with the same
     * and type in the update message must be identical to the set of all records
     * with that name and type on the server.
     *
     * @throws IOException The record could not be parsed.
     */
    @Throws(IOException::class)
    fun present(name: Name, type: Int, record: String) {
        newPrereq(DnsRecord.fromString(name, type, dclass, 0, record, origin))
    }

    /**
     * Parses a record from the tokenizer, and inserts a prerequisite that the
     * record exists.  Due to the way value-dependent prequisites work, the
     * condition that must be met is that the set of all records with the same
     * and type in the update message must be identical to the set of all records
     * with that name and type on the server.
     *
     * @throws IOException The record could not be parsed.
     */
    @Throws(IOException::class)
    fun present(name: Name, type: Int, tokenizer: Tokenizer) {
        newPrereq(DnsRecord.fromString(name, type, dclass, 0, tokenizer, origin))
    }

    /**
     * Inserts a prerequisite that the specified record exists.  Due to the way
     * value-dependent prequisites work, the condition that must be met is that
     * the set of all records with the same and type in the update message must
     * be identical to the set of all records with that name and type on the server.
     */
    fun present(record: DnsRecord) {
        newPrereq(record)
    }

    /**
     * Inserts a prerequisite that the specified name does not exist; that is,
     * there are no records with the given name in the zone.
     */
    fun absent(name: Name) {
        newPrereq(DnsRecord.newRecord(name, DnsRecordType.ANY, DnsClass.NONE, 0))
    }

    /**
     * Inserts a prerequisite that the specified rrset does not exist; that is,
     * there are no records with the given name and type in the zone.
     */
    fun absent(name: Name, type: Int) {
        newPrereq(DnsRecord.newRecord(name, type, DnsClass.NONE, 0))
    }

    /**
     * Indicates that the records should be inserted into the zone.
     */
    fun add(records: Array<DnsRecord>) {
        for (i in records.indices) {
            add(records[i])
        }
    }

    /**
     * Indicates that the record should be inserted into the zone.
     */
    fun add(record: DnsRecord) {
        newUpdate(record)
    }

    private fun newUpdate(rec: DnsRecord) {
        addRecord(rec, DnsSection.UPDATE)
    }

    /**
     * Indicates that all the records in the rrset should be inserted into the
     * zone.
     */
    fun add(rrset: RRset) {
        val it = rrset.rrs()
        while (it.hasNext()) {
            add(it.next() as DnsRecord)
        }
    }

    /**
     * Indicates that all records with the given name should be deleted from
     * the zone.
     */
    fun delete(name: Name) {
        newUpdate(DnsRecord.newRecord(name, DnsRecordType.ANY, DnsClass.ANY, 0))
    }

    /**
     * Parses a record from the string, and indicates that the record
     * should be deleted from the zone.
     *
     * @throws IOException The record could not be parsed.
     */
    @Throws(IOException::class)
    fun delete(name: Name, type: Int, record: String) {
        newUpdate(DnsRecord.fromString(name, type, DnsClass.NONE, 0, record, origin))
    }

    /**
     * Parses a record from the tokenizer, and indicates that the record
     * should be deleted from the zone.
     *
     * @throws IOException The record could not be parsed.
     */
    @Throws(IOException::class)
    fun delete(name: Name, type: Int, tokenizer: Tokenizer) {
        newUpdate(DnsRecord.fromString(name, type, DnsClass.NONE, 0, tokenizer, origin))
    }

    /**
     * Indicates that the records should be deleted from the zone.
     */
    fun delete(records: Array<DnsRecord>) {
        for (i in records.indices) {
            delete(records[i])
        }
    }

    /**
     * Indicates that the specified record should be deleted from the zone.
     */
    fun delete(record: DnsRecord) {
        newUpdate(record.withDClass(DnsClass.NONE, 0))
    }

    /**
     * Indicates that all of the records in the rrset should be deleted from the
     * zone.
     */
    fun delete(rrset: RRset) {
        val it = rrset.rrs()
        while (it.hasNext()) {
            delete(it.next() as DnsRecord)
        }
    }

    /**
     * Parses a record from the string, and indicates that the record
     * should be inserted into the zone replacing any other records with the
     * same name and type.
     *
     * @throws IOException The record could not be parsed.
     */
    @Throws(IOException::class)
    fun replace(name: Name, type: Int, ttl: Long, record: String) {
        delete(name, type)
        add(name, type, ttl, record)
    }

    /**
     * Parses a record from the string, and indicates that the record
     * should be inserted into the zone.
     *
     * @throws IOException The record could not be parsed.
     */
    @Throws(IOException::class)
    fun add(name: Name, type: Int, ttl: Long, record: String) {
        newUpdate(DnsRecord.fromString(name, type, dclass, ttl, record, origin))
    }

    /**
     * Indicates that all records with the given name and type should be deleted
     * from the zone.
     */
    fun delete(name: Name, type: Int) {
        newUpdate(DnsRecord.newRecord(name, type, DnsClass.ANY, 0))
    }

    /**
     * Parses a record from the tokenizer, and indicates that the record
     * should be inserted into the zone replacing any other records with the
     * same name and type.
     *
     * @throws IOException The record could not be parsed.
     */
    @Throws(IOException::class)
    fun replace(name: Name, type: Int, ttl: Long, tokenizer: Tokenizer) {
        delete(name, type)
        add(name, type, ttl, tokenizer)
    }

    /**
     * Parses a record from the tokenizer, and indicates that the record
     * should be inserted into the zone.
     *
     * @throws IOException The record could not be parsed.
     */
    @Throws(IOException::class)
    fun add(name: Name, type: Int, ttl: Long, tokenizer: Tokenizer) {
        newUpdate(DnsRecord.fromString(name, type, dclass, ttl, tokenizer, origin))
    }

    /**
     * Indicates that the records should be inserted into the zone replacing any
     * other records with the same name and type as each one.
     */
    fun replace(records: Array<DnsRecord>) {
        for (i in records.indices) {
            replace(records[i])
        }
    }

    /**
     * Indicates that the record should be inserted into the zone replacing any
     * other records with the same name and type.
     */
    fun replace(record: DnsRecord) {
        delete(record.name, record.type)
        add(record)
    }

    /**
     * Indicates that all the records in the rrset should be inserted into the
     * zone replacing any other records with the same name and type.
     */
    fun replace(rrset: RRset) {
        delete(rrset.name, rrset.type)
        val it = rrset.rrs()
        while (it.hasNext()) {
            add(it.next() as DnsRecord)
        }
    }
}
