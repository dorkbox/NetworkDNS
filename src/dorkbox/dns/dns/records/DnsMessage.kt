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

import dorkbox.dns.dns.Compression
import dorkbox.dns.dns.DnsInput
import dorkbox.dns.dns.DnsOutput
import dorkbox.dns.dns.Name
import dorkbox.dns.dns.constants.DnsClass
import dorkbox.dns.dns.constants.DnsOpCode
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.constants.DnsSection
import dorkbox.dns.dns.constants.Flags
import dorkbox.dns.dns.exceptions.WireParseException
import dorkbox.dns.dns.records.DnsRecord.Companion.fromWire
import dorkbox.os.OS.LINE_SEPARATOR
import io.netty.buffer.ByteBuf
import io.netty.util.AbstractReferenceCounted
import io.netty.util.ReferenceCounted
import io.netty.util.ResourceLeakDetectorFactory

/**
 * A DNS DnsMessage.  A message is the basic unit of communication between
 * the client and server of a DNS operation.  A message consists of a Header
 * and 4 message sections.
 *
 * @author Brian Wellington
 * @see Header
 *
 * @see DnsSection
 */
open class DnsMessage private constructor(var header: Header) : AbstractReferenceCounted(), Cloneable, ReferenceCounted {
    companion object {
        private val leakDetector = ResourceLeakDetectorFactory.instance().newResourceLeakDetector(DnsMessage::class.java)

        /**
         * The maximum length of a message in wire format.
         */
        const val MAXLENGTH = 65535

        /* The message was not signed */
        const val TSIG_UNSIGNED = 0

        /* The message was signed and verification succeeded */
        const val TSIG_VERIFIED = 1

        /* The message was an unsigned message in multiple-message response */
        const val TSIG_INTERMEDIATE = 2

        /* The message was signed and no verification was attempted.  */
        const val TSIG_SIGNED = 3

        /*
         * The message was signed and verification failed, or was not signed
         * when it should have been.
         */
        const val TSIG_FAILED = 4
        private val emptyRecordArray = arrayOf<DnsRecord>()
        private val emptyRRsetArray = arrayOf<RRset>()

        /**
         * Creates a new DnsMessage with a random DnsMessage ID suitable for sending as a
         * query.
         *
         * @param r A record containing the question
         */
        @JvmStatic
        fun newQuery(r: DnsRecord): DnsMessage {
            val m = DnsMessage()
            m.header.opcode = DnsOpCode.QUERY
            m.header.setFlag(Flags.RD)
            m.addRecord(r, DnsSection.QUESTION)
            return m
        }

        /**
         * Creates a new DnsMessage to contain a dynamic update.  A random DnsMessage ID
         * and the zone are filled in.
         *
         * @param zone The zone to be updated
         */
        fun newUpdate(zone: Name): DnsMessage {
            return Update(zone)
        }

        private fun <T : DnsRecord?> castRecord(record: Any): T {
            return record as T
        }

        private fun newRecordList(count: Int): ArrayList<DnsRecord?> {
            return ArrayList(count)
        }

        private fun newRecordList(): ArrayList<DnsRecord?> {
            return ArrayList(2)
        }

        private fun sameSet(r1: DnsRecord, r2: DnsRecord): Boolean {
            return r1.rRsetType == r2.rRsetType && r1.dclass == r2.dclass && r1.name.equals(r2.name)
        }
    }


    private val leakTracking = leakDetector.track(this)


    // To reduce the memory footprint of a message,
    // each of the following fields is a single record or a list of records.
    private var questions: Any? = null
    private var answers: Any? = null
    private var authorities: Any? = null
    private var additionals: Any? = null

    private var size = 0
    private var tsigkey: TSIG? = null
    private var querytsig: TSIGRecord? = null
    private var tsigerror = 0

    var tsigstart = 0
    var tsigState = 0
    var sig0start = 0

    /**
     * Creates a new DnsMessage with the specified DnsMessage ID
     */
    constructor(id: Int) : this(Header(id)) {}

    /**
     * Creates a new DnsMessage with a random DnsMessage ID
     */
    constructor() : this(Header()) {}

    /**
     * Creates a new DnsMessage from its DNS wire format representation
     *
     * @param byteArray A byte array containing the DNS DnsMessage.
     */
    constructor(byteArray: ByteArray) : this(DnsInput(byteArray))

    /**
     * Creates a new DnsMessage from its DNS wire format representation
     *
     * @param dnsInput A DnsInput containing the DNS DnsMessage.
     */
    constructor(dnsInput: DnsInput) : this(Header(dnsInput)) {
        val isUpdate = header.opcode == DnsOpCode.UPDATE
        val truncated = header.getFlag(Flags.TC)

        try {
            for (i in 0 until DnsSection.TOTAL_SECTION_COUNT) {
                val count = header.getCount(i)
                var records: MutableList<DnsRecord?>
                if (count > 0) {
                    records = newRecordList(count)
                    setSection(i, records)

                    for (j in 0 until count) {
                        val pos = dnsInput.readIndex()
                        val record = fromWire(dnsInput, i, isUpdate)
                        records.add(record)

                        if (i == DnsSection.ADDITIONAL) {
                            if (record.type == DnsRecordType.TSIG) {
                                tsigstart = pos
                            }
                            else if (record.type == DnsRecordType.SIG) {
                                val sig = record as SIGRecord
                                if (sig.typeCovered == 0) {
                                    sig0start = pos
                                }
                            }
                        }
                    }
                }
            }
        } catch (e: WireParseException) {
            if (!truncated) {
                throw e
            }
        }
        size = dnsInput.readIndex()
    }

    /**
     * Creates a new DnsMessage from its DNS wire format representation
     *
     * @param byteBuffer A ByteBuf containing the DNS DnsMessage.
     */
    constructor(byteBuffer: ByteBuf) : this(DnsInput(byteBuffer))

    private fun sectionAt(section: Int): Any? {
        when (section) {
            DnsSection.QUESTION -> return questions
            DnsSection.ANSWER -> return answers
            DnsSection.AUTHORITY -> return authorities
            DnsSection.ADDITIONAL -> return additionals
        }

        throw IndexOutOfBoundsException() // Should never reach here.
    }

    private fun setSection(section: Int, value: Any?) {
        when (section) {
            DnsSection.QUESTION -> {
                questions = value
                return
            }
            DnsSection.ANSWER -> {
                answers = value
                return
            }
            DnsSection.AUTHORITY -> {
                authorities = value
                return
            }
            DnsSection.ADDITIONAL -> {
                additionals = value
                return
            }
        }
        throw IndexOutOfBoundsException() // Should never reach here.
    }

    /**
     * Adds a record to a section of the DnsMessage, and adjusts the header.
     *
     * @see DnsRecord
     *
     * @see DnsSection
     */
    fun addRecord(record: DnsRecord, section: Int) {
        val records = sectionAt(section)

        header.incCount(section)
        if (records == null) {
            // it holds no records, so add a single record...
            setSection(section, record)
            return
        }

        if (records is DnsRecord) {
            // it holds a single record, so convert it to multiple records
            val recordList: MutableList<DnsRecord?> = newRecordList()
            recordList.add(castRecord<DnsRecord>(records))
            recordList.add(record)
            setSection(section, recordList)
            return
        }

        // holds a list of records
        val recordList = records as MutableList<DnsRecord>
        recordList.add(record)
    }

    /**
     * Removes a record from a section of the DnsMessage, and adjusts the header.
     *
     * @see DnsRecord
     *
     * @see DnsSection
     */
    fun removeRecord(record: DnsRecord, section: Int): Boolean {
        val records = sectionAt(section) ?: return false // can't remove a record if there are none
        if (records is DnsRecord) {
            setSection(section, null)
            header.decCount(section)
            return true
        }

        val recordList = records as MutableList<DnsRecord>
        val remove = recordList.remove(record)
        if (remove) {
            header.decCount(section)
            return true
        }

        return false
    }

    /**
     * Removes all records from a section of the DnsMessage, and adjusts the header.
     *
     * @see DnsRecord
     *
     * @see DnsSection
     */
    fun removeAllRecords(section: Int) {
        setSection(section, null)
        header.setCount(section, 0)
    }

    /**
     * Determines if the given record is already present in the given section.
     *
     * @see DnsRecord
     *
     * @see DnsSection
     */
    fun findRecord(record: DnsRecord, section: Int): Boolean {
        val records = sectionAt(section) ?: return false
        if (records is DnsRecord) {
            return records == record
        }

        val recordList = records as List<DnsRecord>
        return recordList.contains(record)
    }

    /**
     * Determines if the given record is already present in any section.
     *
     * @see DnsRecord
     *
     * @see DnsSection
     */
    fun findRecord(record: DnsRecord): Boolean {
        for (i in DnsSection.ANSWER..DnsSection.ADDITIONAL) {
            if (findRecord(record, i)) {
                return true
            }
        }

        return false
    }

    /**
     * Determines if an RRset with the given name and type is already
     * present in any section.
     *
     * @see RRset
     *
     * @see DnsSection
     */
    fun findRRset(name: Name, type: Int): Boolean {
        return findRRset(name, type, DnsSection.ANSWER) ||
               findRRset(name, type, DnsSection.AUTHORITY) ||
               findRRset(name, type, DnsSection.ADDITIONAL
        )
    }

    /**
     * Determines if an RRset with the given name and type is already
     * present in the given section.
     *
     * @see RRset
     *
     * @see DnsSection
     */
    fun findRRset(name: Name, type: Int, section: Int): Boolean {
        val record = sectionAt(section) ?: return false
        if (record is DnsRecord) {
            return record.type == type && name == record.name
        }

        // this is a list instead of a single entry
        val recordList = record as List<DnsRecord>
        for (i in recordList.indices) {
            val record = recordList[i]
            if (record.type == type && name == record.name) {
                return true
            }
        }

        return false
    }

    /**
     * Returns the first record in the QUESTION section.
     *
     * @see DnsRecord
     *
     * @see DnsSection
     */
    val question: DnsRecord?
        get() {
            val records = sectionAt(DnsSection.QUESTION) ?: return null
            if (records is DnsRecord) {
                return records
            }

            val recordList = records as List<DnsRecord>
            return recordList[0]
        }

    /**
     * Returns the TSIG record from the ADDITIONAL section, if one is present.
     *
     * @see TSIGRecord
     *
     * @see TSIG
     *
     * @see DnsSection
     */
    val tSIG: TSIGRecord?
        get() {
            val records = sectionAt(DnsSection.ADDITIONAL) ?: return null
            if (records is DnsRecord) {
                val record = records
                return if (record.type != DnsRecordType.TSIG) {
                    null
                } else {
                    record as TSIGRecord
                }
            }

            val recordList = records as List<DnsRecord>
            val record = recordList[recordList.size - 1]

            return if (record.type != DnsRecordType.TSIG) {
                null
            } else {
                record as TSIGRecord
            }
        }

    /**
     * Returns an array containing all records in the given section grouped into RRsets.
     *
     * @see RRset
     *
     * @see DnsSection
     */
    fun getSectionRRsets(section: Int): Array<RRset> {
        val records = sectionAt(section) ?: return emptyRRsetArray
        val sets: MutableList<RRset> = ArrayList(header.getCount(section))
        val hash = mutableSetOf<Name>()

        if (records is DnsRecord) {
            // only 1, so no need to make it complicated
            return arrayOf(RRset(records))
        }


        // now there are multiple records
        val recordList = records as List<DnsRecord>
        for (i in recordList.indices) {
            val record = recordList[i]
            val name: Name = record.name
            var newset = true

            if (hash.contains(name)) {
                for (j in sets.indices.reversed()) {
                    val set = sets[j]
                    if (set.type == record.rRsetType && set.dClass == record.dclass && set.name == name) {
                        set.addRR(record)
                        newset = false
                        break
                    }
                }
            }


            if (newset) {
                val set = RRset(record)
                sets.add(set)
                hash.add(name)
            }
        }
        return sets.toTypedArray()
    }

    /**
     * Returns an array containing all records in the given section, or an
     * empty array if the section is empty.
     *
     * @see DnsRecord
     *
     * @see DnsSection
     */
    fun getSectionArray(section: Int): Array<DnsRecord> {
        val records = sectionAt(section) ?: return emptyRecordArray
        if (records is DnsRecord) {
            // only 1, so no need to make it complicated
            return arrayOf(records)
        }

        val recordList = records as List<DnsRecord>
        return recordList.toTypedArray()
    }

    /**
     * Returns an array containing the wire format representation of the DnsMessage.
     */
    fun toWire(): ByteArray {
        val out = DnsOutput()
        toWire(out)
        size = out.current()
        return out.toByteArray()
    }

    fun toWire(out: DnsOutput) {
        header.toWire(out)
        val c = Compression()
        for (i in 0 until DnsSection.TOTAL_SECTION_COUNT) {
            val records = sectionAt(i) ?: continue
            if (records is DnsRecord) {
                records.toWire(out, i, c)
                continue
            }

            val recordList = records as List<DnsRecord>
            for (j in recordList.indices) {
                val record = recordList[j]
                record.toWire(out, i, c)
            }
        }
    }

    /**
     * Returns an array containing the wire format representation of the DnsMessage
     * with the specified maximum length.  This will generate a truncated
     * message (with the TC bit) if the message doesn't fit, and will also
     * sign the message with the TSIG key set by a call to setTSIG().  This
     * method may return null if the message could not be rendered at all; this
     * could happen if maxLength is smaller than a DNS header, for example.
     *
     * @param maxLength The maximum length of the message.
     *
     * @return The wire format of the message, or null if the message could not be
     * rendered into the specified length.
     *
     * @see Flags
     *
     * @see TSIG
     */
    fun toWire(maxLength: Int): ByteArray {
        val out = DnsOutput()
        // this will also prep the output stream.
        val b = toWire(out, maxLength)
        if (!b) {
            System.err.println("ERROR CREATING MESSAGE FROM WIRE!")
        }
        size = out.current()

        // we output from the start.
        out.byteBuf.readerIndex(0)
        return out.toByteArray()
    }

    /** Returns true if the message could be rendered.  */
    private fun toWire(out: DnsOutput, maxLength: Int): Boolean {
        if (maxLength < Header.LENGTH) {
            return false
        }
        var tempMaxLength = maxLength
        if (tsigkey != null) {
            tempMaxLength -= tsigkey!!.recordLength()
        }

        val opt = optRecord
        var optBytes: ByteArray? = null
        if (opt != null) {
            optBytes = opt.toWire(DnsSection.ADDITIONAL)
            tempMaxLength -= optBytes.size
        }

        val startpos = out.current()
        header.toWire(out)


        val c = Compression()
        var flags = header.flagsByte
        var additionalCount = 0
        for (i in 0 until DnsSection.TOTAL_SECTION_COUNT) {
            var skipped: Int
            val records = sectionAt(i) ?: continue

            skipped = sectionToWire(out, i, c, tempMaxLength)
            if (skipped != 0 && i != DnsSection.ADDITIONAL) {
                flags = Header.setFlag(flags, Flags.TC, true)
                out.writeU16At(header.getCount(i) - skipped, startpos + 4 + 2 * i)
                for (j in i + 1 until DnsSection.ADDITIONAL) {
                    out.writeU16At(0, startpos + 4 + 2 * j)
                }
                break
            }
            if (i == DnsSection.ADDITIONAL) {
                additionalCount = header.getCount(i) - skipped
            }
        }

        if (optBytes != null) {
            out.writeByteArray(optBytes)
            additionalCount++
        }

        if (flags != header.flagsByte) {
            out.writeU16At(flags, startpos + 2)
        }

        if (additionalCount != header.getCount(DnsSection.ADDITIONAL)) {
            out.writeU16At(additionalCount, startpos + 10)
        }

        if (tsigkey != null) {
            val tsigrec = tsigkey!!.generate(this, out.toByteArray(), tsigerror, querytsig)
            tsigrec.toWire(out, DnsSection.ADDITIONAL, c)
            // write size/position info
            out.writeU16At(additionalCount + 1, startpos + 10)
        }

        return true
    }

    /**
     * Returns the OPT record from the ADDITIONAL section, if one is present.
     *
     * @see OPTRecord
     *
     * @see DnsSection
     */
    val optRecord: OPTRecord?
        get() {
            val additional = getSectionArray(DnsSection.ADDITIONAL)
            for (i in additional.indices) {
                if (additional[i] is OPTRecord) {
                    return additional[i] as OPTRecord?
                }
            }
            return null
        }

    /** Returns the number of records not successfully rendered.  */
    private fun sectionToWire(out: DnsOutput, section: Int, c: Compression, maxLength: Int): Int {
        val records = sectionAt(section)
        // will never be null, we check earlier
        var pos = out.current()
        var rendered = 0
        var skipped = 0
        var lastRecord: DnsRecord? = null

        if (records is DnsRecord) {
            val record = records
            if (section == DnsSection.ADDITIONAL && record.type == DnsRecordType.OPT) {
                skipped++
                return skipped
            }

            record.toWire(out, section, c)
            if (out.current() > maxLength) {
                out.jump(pos)
                return 1 - rendered + skipped
            }

            return skipped
        }


        val recordList = records as List<DnsRecord>?
        val n = recordList!!.size
        for (i in 0 until n) {
            val record = recordList[i]
            if (section == DnsSection.ADDITIONAL && record.type == DnsRecordType.OPT) {
                skipped++
                continue
            }

            if (lastRecord != null && !sameSet(record, lastRecord)) {
                pos = out.current()
                rendered = i
            }

            lastRecord = record
            record.toWire(out, section, c)

            if (out.current() > maxLength) {
                out.jump(pos)
                return n - rendered + skipped
            }
        }
        return skipped
    }

    /**
     * Sets the TSIG key and other necessary information to sign a message.
     *
     * @param key The TSIG key.
     * @param error The value of the TSIG error field.
     * @param querytsig If this is a response, the TSIG from the request.
     */
    fun setTSIG(key: TSIG?, error: Int, querytsig: TSIGRecord?) {
        tsigkey = key
        tsigerror = error
        this.querytsig = querytsig
    }

    /**
     * Creates a SHALLOW copy of this DnsMessage.  This is done by the Resolver before adding
     * TSIG and OPT records, for example.
     *
     * @see TSIGRecord
     *
     * @see OPTRecord
     */
    public override fun clone(): Any {
        val m = DnsMessage()
        for (i in 0 until DnsSection.TOTAL_SECTION_COUNT) {
            val records = sectionAt(i) ?: continue
            if (records is DnsRecord) {
                setSection(i, records)
                continue
            }

            val recordList = records as List<DnsRecord>
            setSection(i, ArrayList(recordList))
        }

        m.header = header.clone() as Header
        m.size = size
        return m
    }

    /**
     * Converts the DnsMessage to a String.
     */
    override fun toString(): String {
        val NL = LINE_SEPARATOR
        val sb = StringBuilder(NL)
        val opt = optRecord

        if (opt != null) {
            sb.append(header.toStringWithRcode(rcode)).append(NL)
        } else {
            sb.append(header).append(NL)
        }


        if (isSigned) {
            sb.append(";; TSIG ")
            if (isVerified) {
                sb.append("ok")
            } else {
                sb.append("invalid")
            }
            sb.append(NL)
        }


        for (i in 0..3) {
            if (header.opcode != DnsOpCode.UPDATE) {
                sb.append(";; ").append(DnsSection.longString(i)).append(":").append(NL)
            } else {
                sb.append(";; ").append(DnsSection.updString(i)).append(":").append(NL)
            }
            sb.append(sectionToString(i)).append(NL)
        }
        sb.append(";; DnsMessage size: ").append(numBytes()).append(" bytes")
        return sb.toString()
    }

    /**
     * Was this message signed by a TSIG?
     *
     * @see TSIG
     */
    val isSigned: Boolean
        get() = tsigState == TSIG_SIGNED || tsigState == TSIG_VERIFIED || tsigState == TSIG_FAILED

    /**
     * If this message was signed by a TSIG, was the TSIG verified?
     *
     * @see TSIG
     */
    val isVerified: Boolean
        get() = tsigState == TSIG_VERIFIED


    /**
     * Returns the message's rcode (error code).  This incorporates the EDNS
     * extended rcode.
     */
    val rcode: Int
        get() {
            var rcode = header.rcode
            val opt = optRecord
            if (opt != null) {
                rcode += opt.extendedRcode shl 4
            }
            return rcode
        }


    /**
     * Returns the size of the message.  Only valid if the message has been converted to or from wire format.
     */
    fun numBytes(): Int {
        return size
    }

    /**
     * Converts the given section of the DnsMessage to a String.
     *
     * @see DnsSection
     */
    fun sectionToString(i: Int): String? {
        if (i > 3) {
            return null
        }
        val sb = StringBuilder()
        val records = getSectionArray(i)
        for (j in records.indices) {
            val rec = records[j]

            if (i == DnsSection.QUESTION) {
                sb.append(";;\t").append(rec.name)
                sb.append(", type = ").append(DnsRecordType.string(rec.type))
                sb.append(", class = ").append(DnsClass.string(rec.dclass))
            } else {
                sb.append(rec)
            }
            sb.append(LINE_SEPARATOR)
        }
        return sb.toString()
    }

    /**
     * Removes all the records in this DNS message.
     */
    fun clear(): DnsMessage {
        for (i in 0 until DnsSection.TOTAL_SECTION_COUNT) {
            removeAllRecords(i)
        }

        return this
    }

    override fun deallocate() {
        clear()
        val leak = leakTracking
        if (leak != null) {
            val closed = leak.close(this)
            assert(closed)
        }
    }

    override fun touch(hint: Any): DnsMessage {
        leakTracking?.record(hint)
        return this
    }
}
