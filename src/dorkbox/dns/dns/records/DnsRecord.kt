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
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.constants.DnsSection
import dorkbox.dns.dns.exceptions.RelativeNameException
import dorkbox.dns.dns.exceptions.TextParseException
import dorkbox.dns.dns.exceptions.WireParseException
import dorkbox.dns.dns.utils.Options
import dorkbox.dns.dns.utils.Tokenizer
import dorkbox.dns.dns.utils.base16
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.Serializable
import java.text.DecimalFormat
import java.util.*

/**
 * A generic DNS resource record.  The specific record types extend this class.
 * A record contains a name, type, class, ttl, and rdata.
 *
 * @author Brian Wellington
 */
abstract class DnsRecord() : Cloneable, Comparable<Any?>, Serializable {
    /**
     * Returns the record's name
     *
     * @see Name
     */
    lateinit var name: Name

    /**
     * Returns the record's type
     *
     * @see DnsRecordType
     */
    var type: Int = 0

    /**
     * Returns the record's class
     */
    var dclass: Int = 0

    /**
     * Returns the record's TTL
     */
    var ttl: Long = 0

    /**
     * Creates an empty record of the correct type; must be overriden
     */
    abstract val `object`: DnsRecord

    protected constructor(name: Name, type: Int, dclass: Int, ttl: Long) : this() {
        if (!name.isAbsolute) {
            throw RelativeNameException(name)
        }
        DnsRecordType.check(type)
        DnsClass.check(dclass)
        TTL.check(ttl)

        this.name = name
        this.type = type
        this.dclass = dclass
        this.ttl = ttl
    }

    /**
     * Converts the type-specific RR to wire format - must be overriden
     */
    @Throws(IOException::class)
    abstract fun rrFromWire(`in`: DnsInput)

    /**
     * Converts a Record into DNS uncompressed wire format.
     */
    fun toWire(section: Int): ByteArray {
        val out = DnsOutput()
        toWire(out, section, null)
        return out.toByteArray()
    }

    fun toWire(out: DnsOutput, section: Int, c: Compression?) {
        name.toWire(out, c)
        out.writeU16(type)
        out.writeU16(dclass)
        if (section == DnsSection.QUESTION) {
            return
        }
        out.writeU32(ttl)
        val lengthPosition = out.current()
        out.writeU16(0) /* until we know better */
        rrToWire(out, c, false)
        val rrlength = out.current() - lengthPosition - 2
        out.writeU16At(rrlength, lengthPosition)
    }

    /**
     * Converts the type-specific RR to wire format - must be overriden
     */
    abstract fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean)

    /**
     * Converts a Record into canonical DNS uncompressed wire format (all names are
     * converted to lowercase).
     */
    fun toWireCanonical(): ByteArray {
        return toWireCanonical(false)
    }

    /*
     * Converts a Record into canonical DNS uncompressed wire format (all names are
     * converted to lowercase), optionally ignoring the TTL.
     */
    private fun toWireCanonical(noTTL: Boolean): ByteArray {
        val out = DnsOutput()
        toWireCanonical(out, noTTL)
        return out.toByteArray()
    }

    private fun toWireCanonical(out: DnsOutput, noTTL: Boolean) {
        name.toWireCanonical(out)
        out.writeU16(type)
        out.writeU16(dclass)
        if (noTTL) {
            out.writeU32(0)
        } else {
            out.writeU32(ttl)
        }
        val lengthPosition = out.current()
        out.writeU16(0) /* until we know better */
        rrToWire(out, null, true)
        val rrlength = out.current() - lengthPosition - 2
        out.writeU16At(rrlength, lengthPosition)
    }

    /**
     * Converts the rdata portion of a Record into a String representation
     */
    fun rdataToString(sb: StringBuilder) {
        rrToString(sb)
    }

    /**
     * Converts the type-specific RR to text format - must be overriden
     */
    abstract fun rrToString(sb: StringBuilder)

    /**
     * Converts the text format of an RR to the internal format - must be overriden
     */
    @Throws(IOException::class)
    abstract fun rdataFromString(st: Tokenizer, origin: Name?)

    /**
     * Determines if two Records could be part of the same RRset.
     * This compares the name, type, and class of the Records; the ttl and
     * rdata are not compared.
     */
    fun sameRRset(rec: DnsRecord): Boolean {
        return rRsetType == rec.rRsetType && dclass == rec.dclass && name == rec.name
    }

    /**
     * Returns the type of RRset that this record would belong to.  For all types
     * except RRSIG, this is equivalent to getType().
     *
     * @return The type of record, if not RRSIG.  If the type is RRSIG,
     * the type covered is returned.
     *
     * @see DnsRecordType
     *
     * @see RRset
     *
     * @see SIGRecord
     */
    val rRsetType: Int
        get() {
            if (type == DnsRecordType.RRSIG) {
                val sig = this as RRSIGRecord
                return sig.typeCovered
            }
            return type
        }

    /**
     * Generates a hash code based on the Record's data.
     */
    override fun hashCode(): Int {
        val array = toWireCanonical(true)
        var code = 0
        for (i in array.indices) {
            code += (code shl 3) + (array[i].toInt() and 0xFF)
        }
        return code
    }

    /**
     * Determines if two Records are identical.  This compares the name, type,
     * class, and rdata (with names canonicalized).  The TTLs are not compared.
     *
     * @param arg The record to compare to
     *
     * @return true if the records are equal, false otherwise.
     */
    override fun equals(arg: Any?): Boolean {
        if (arg == null || arg !is DnsRecord) {
            return false
        }
        val r = arg
        if (type != r.type || dclass != r.dclass || name != r.name) {
            return false
        }
        val array1 = rdataToWireCanonical()
        val array2 = r.rdataToWireCanonical()
        return Arrays.equals(array1, array2)
    }

    /**
     * Converts the rdata in a Record into canonical DNS uncompressed wire format
     * (all names are converted to lowercase).
     */
    fun rdataToWireCanonical(): ByteArray {
        val out = DnsOutput()
        rrToWire(out, null, true)
        return out.toByteArray()
    }

    /**
     * Converts a Record into a String representation
     */
    override fun toString(): String {
        val sb = StringBuilder()
        toString(sb)
        return sb.toString()
    }

    /**
     * Converts a Record into a String representation in a StringBuilder
     */
    fun toString(sb: StringBuilder) {
        sb.append(name)
        if (sb.length < 8) {
            sb.append("\t")
        }
        if (sb.length < 16) {
            sb.append("\t")
        }
        sb.append("\t")
        if (Options.check("BINDTTL")) {
            sb.append(TTL.format(ttl))
        } else {
            sb.append(ttl)
        }
        sb.append("\t")
        if (dclass != DnsClass.IN || !Options.check("noPrintIN")) {
            sb.append(DnsClass.string(dclass))
            sb.append("\t")
        }
        sb.append(DnsRecordType.string(type))
        sb.append("\t")
        val length = sb.length
        rrToString(sb)
        if (length == sb.length) {
            // delete the /t since we had no record data
            sb.deleteCharAt(length - 1)
        }
    }

    /**
     * Creates a new record identical to the current record, but with a different
     * name.  This is most useful for replacing the name of a wildcard record.
     */
    fun withName(name: Name): DnsRecord {
        if (!name.isAbsolute) {
            throw RelativeNameException(name)
        }
        val rec = cloneRecord()
        rec.name = name
        return rec
    }

    fun cloneRecord(): DnsRecord {
        return try {
            clone() as DnsRecord
        } catch (e: CloneNotSupportedException) {
            throw IllegalStateException()
        }
    }

    /**
     * Creates a new record identical to the current record, but with a different
     * class and ttl.  This is most useful for dynamic update.
     */
    fun withDClass(dclass: Int, ttl: Long): DnsRecord {
        val rec = cloneRecord()
        rec.dclass = dclass
        rec.ttl = ttl
        return rec
    }

    /**
     * Compares this Record to another Object.
     *
     * @param other The Object to be compared.
     *
     * @return The value 0 if the argument is a record equivalent to this record;
     * a value less than 0 if the argument is less than this record in the
     * canonical ordering, and a value greater than 0 if the argument is greater
     * than this record in the canonical ordering.  The canonical ordering
     * is defined to compare by name, class, type, and rdata.
     *
     * @throws ClassCastException if the argument is not a Record.
     */
    override fun compareTo(other: Any?): Int {
        val arg = other as DnsRecord?
        if (this === arg) {
            return 0
        }

        if (other == null) {
            return -1
        }

        var n = name.compareTo(arg!!.name)
        if (n != 0) {
            return n
        }
        n = dclass - arg.dclass
        if (n != 0) {
            return n
        }
        n = type - arg.type
        if (n != 0) {
            return n
        }
        val rdata1 = rdataToWireCanonical()
        val rdata2 = arg.rdataToWireCanonical()
        var i = 0
        while (i < rdata1.size && i < rdata2.size) {
            n = (rdata1[i].toInt() and 0xFF) - (rdata2[i].toInt() and 0xFF)
            if (n != 0) {
                return n
            }
            i++
        }
        return rdata1.size - rdata2.size
    }

    /**
     * Returns the name for which additional data processing should be done
     * for this record.  This can be used both for building responses and
     * parsing responses.
     *
     * @return The name to used for additional data processing, or null if this
     * record type does not require additional data processing.
     */
    open var additionalName: Name? = null

    companion object {
        private const val serialVersionUID = 2694906050116005466L
        private val byteFormat = DecimalFormat()

        init {
            byteFormat.minimumIntegerDigits = 3
        }

        /**
         * Creates a new record, with the given parameters.
         *
         * @param name The owner name of the record.
         * @param type The record's type.
         * @param dclass The record's class.
         * @param ttl The record's time to live.
         * @param data The complete rdata of the record, in uncompressed DNS wire
         * format.
         */
        fun newRecord(name: Name, type: Int, dclass: Int, ttl: Long, data: ByteArray): DnsRecord? {
            return newRecord(name, type, dclass, ttl, data.size, data)
        }

        /**
         * Creates a new record, with the given parameters.
         *
         * @param name The owner name of the record.
         * @param type The record's type.
         * @param dclass The record's class.
         * @param ttl The record's time to live.
         * @param length The length of the record's data.
         * @param data The rdata of the record, in uncompressed DNS wire format.  Only
         * the first length bytes are used.
         */
        fun newRecord(name: Name, type: Int, dclass: Int, ttl: Long, length: Int, data: ByteArray?): DnsRecord? {
            if (!name.isAbsolute) {
                throw RelativeNameException(name)
            }

            DnsRecordType.check(type)
            DnsClass.check(dclass)
            TTL.check(ttl)

            val `in` = data?.let { DnsInput(it) }
            return try {
                newRecord(name, type, dclass, ttl, length, `in`)
            } catch (e: IOException) {
                null
            }
        }

        @Throws(IOException::class)
        private fun newRecord(name: Name, type: Int, dclass: Int, ttl: Long, length: Int, `in`: DnsInput?): DnsRecord {
            val rec = getEmptyRecord(name, type, dclass, ttl, `in` != null)
            if (`in` != null) {
                if (`in`.remaining() < length) {
                    throw WireParseException("truncated record")
                }
                `in`.setActive(length)
                rec.rrFromWire(`in`)
                val remaining = `in`.remaining()
                `in`.restoreActive()
                if (remaining > 0) {
                    throw WireParseException("invalid record length")
                }
            }
            return rec
        }

        private fun getEmptyRecord(name: Name, type: Int, dclass: Int, ttl: Long, hasData: Boolean): DnsRecord {
            val proto: DnsRecord?
            val rec: DnsRecord

            if (hasData) {
                proto = DnsRecordType.getProto(type)
                rec = proto?.`object` ?: UNKRecord()
            } else {
                rec = EmptyRecord()
            }

            rec.name = name
            rec.type = type
            rec.dclass = dclass
            rec.ttl = ttl
            return rec
        }
        /**
         * Creates a new empty record, with the given parameters.
         *
         * @param name The owner name of the record.
         * @param type The record's type.
         * @param dclass The record's class.
         * @param ttl The record's time to live.
         *
         * @return An object of a subclass of Record
         */
        fun newRecord(name: Name, type: Int, dclass: Int, ttl: Long = 0): DnsRecord {
            if (!name.isAbsolute) {
                throw RelativeNameException(name)
            }
            DnsRecordType.check(type)
            DnsClass.check(dclass)
            TTL.check(ttl)
            return getEmptyRecord(name, type, dclass, ttl, false)
        }

        @Throws(IOException::class)
        fun fromWire(`in`: DnsInput, section: Int, isUpdate: Boolean = false): DnsRecord {
            val type: Int
            val dclass: Int
            val ttl: Long
            val length: Int
            val name: Name
            val rec: DnsRecord
            name = Name(`in`)
            type = `in`.readU16()
            dclass = `in`.readU16()
            if (section == DnsSection.QUESTION) {
                return newRecord(name, type, dclass)
            }
            ttl = `in`.readU32()
            length = `in`.readU16()
            if (length == 0 && isUpdate && (section == DnsSection.PREREQ || section == DnsSection.UPDATE)) {
                return newRecord(name, type, dclass, ttl)
            }
            rec = newRecord(name, type, dclass, ttl, length, `in`)
            return rec
        }

        /**
         * Builds a Record from DNS uncompressed wire format.
         */
        @Throws(IOException::class)
        fun fromWire(b: ByteArray, section: Int): DnsRecord {
            return fromWire(DnsInput(b), section, false)
        }

        /**
         * Converts a String into a byte array.
         */
        @JvmStatic
        @Throws(TextParseException::class)
        fun byteArrayFromString(s: String): ByteArray {
            var array = s.toByteArray()
            var escaped = false
            var hasEscapes = false
            for (i in array.indices) {
                if (array[i] == '\\'.code.toByte()) {
                    hasEscapes = true
                    break
                }
            }
            if (!hasEscapes) {
                if (array.size > 255) {
                    throw TextParseException("text string too long")
                }
                return array
            }
            val os = ByteArrayOutputStream()
            var digits = 0
            var intval = 0
            for (i in array.indices) {
                var b = array[i]
                if (escaped) {
                    if (b >= '0'.code.toByte() && b <= '9'.code.toByte() && digits < 3) {
                        digits++
                        intval *= 10
                        intval += b - '0'.code.toByte()
                        if (intval > 255) {
                            throw TextParseException("bad escape")
                        }
                        if (digits < 3) {
                            continue
                        }
                        b = intval.toByte()
                    } else if (digits > 0 && digits < 3) {
                        throw TextParseException("bad escape")
                    }
                    os.write(b.toInt())
                    escaped = false
                } else if (array[i] == '\\'.code.toByte()) {
                    escaped = true
                    digits = 0
                    intval = 0
                } else {
                    os.write(array[i].toInt())
                }
            }
            if (digits > 0 && digits < 3) {
                throw TextParseException("bad escape")
            }
            array = os.toByteArray()
            if (array.size > 255) {
                throw TextParseException("text string too long")
            }
            return os.toByteArray()
        }

        /**
         * Converts a byte array into a String.
         */
        @JvmStatic
        fun byteArrayToString(array: ByteArray, quote: Boolean): String {
            val sb = StringBuilder()
            if (quote) {
                sb.append('"')
            }
            for (i in array.indices) {
                val b = array[i].toInt() and 0xFF
                if (b < 0x20 || b >= 0x7f) {
                    sb.append('\\')
                    sb.append(byteFormat.format(b.toLong()))
                } else if (b == '"'.code || b == '\\'.code) {
                    sb.append('\\')
                    sb.append(b.toChar())
                } else {
                    sb.append(b.toChar())
                }
            }
            if (quote) {
                sb.append('"')
            }
            return sb.toString()
        }

        /**
         * Converts a byte array into the unknown RR format.
         */
        fun unknownToString(data: ByteArray): String {
            val sb = StringBuilder()
            sb.append("\\# ")
            sb.append(data.size)
            sb.append(" ")
            sb.append(base16.toString(data))
            return sb.toString()
        }

        /**
         * Builds a new Record from its textual representation
         *
         * @param name The owner name of the record.
         * @param type The record's type.
         * @param dclass The record's class.
         * @param ttl The record's time to live.
         * @param st A tokenizer containing the textual representation of the rdata.
         * @param origin The default origin to be appended to relative domain names.
         *
         * @return The new record
         *
         * @throws IOException The text format was invalid.
         */
        @Throws(IOException::class)
        fun fromString(name: Name, type: Int, dclass: Int, ttl: Long, st: Tokenizer, origin: Name?): DnsRecord {
            val rec: DnsRecord
            if (!name.isAbsolute) {
                throw RelativeNameException(name)
            }
            DnsRecordType.check(type)
            DnsClass.check(dclass)
            TTL.check(ttl)
            var t = st.get()
            if (t.type == Tokenizer.IDENTIFIER && t.value == "\\#") {
                val length = st.getUInt16()
                var data = st.hex
                if (data == null) {
                    data = ByteArray(0)
                }
                if (length != data.size) {
                    throw st.exception("invalid unknown RR encoding: " + "length mismatch")
                }
                val `in` = DnsInput(data)
                return newRecord(name, type, dclass, ttl, length, `in`)
            }
            st.unget()
            rec = getEmptyRecord(name, type, dclass, ttl, true)
            rec.rdataFromString(st, origin)
            t = st.get()
            if (t.type != Tokenizer.EOL && t.type != Tokenizer.EOF) {
                throw st.exception("unexpected tokens at end of record")
            }
            return rec
        }

        /**
         * Builds a new Record from its textual representation
         *
         * @param name The owner name of the record.
         * @param type The record's type.
         * @param dclass The record's class.
         * @param ttl The record's time to live.
         * @param s The textual representation of the rdata.
         * @param origin The default origin to be appended to relative domain names.
         *
         * @return The new record
         *
         * @throws IOException The text format was invalid.
         */
        @Throws(IOException::class)
        fun fromString(name: Name, type: Int, dclass: Int, ttl: Long, s: String, origin: Name?): DnsRecord {
            return fromString(name, type, dclass, ttl, Tokenizer(s), origin)
        }

        /* Checks that an int contains an unsigned 8 bit value */
        fun checkU8(field: String, `val`: Int): Int {
            require(!(`val` < 0 || `val` > 0xFF)) { "\"$field\" $`val` must be an unsigned 8 bit value" }
            return `val`
        }

        /* Checks that an int contains an unsigned 16 bit value */
        fun checkU16(field: String, `val`: Int): Int {
            require(!(`val` < 0 || `val` > 0xFFFF)) { "\"$field\" $`val` must be an unsigned 16 bit value" }
            return `val`
        }

        /* Checks that a long contains an unsigned 32 bit value */
        fun checkU32(field: String, `val`: Long): Long {
            require(!(`val` < 0 || `val` > 0xFFFFFFFFL)) { "\"$field\" $`val` must be an unsigned 32 bit value" }
            return `val`
        }

        /* Checks that a name is absolute */
        fun checkName(field: String, name: Name): Name {
            if (!name.isAbsolute) {
                throw RelativeNameException("$field is not relative ($name)!")
            }
            return name
        }

        fun checkByteArrayLength(field: String, array: ByteArray, maxLength: Int): ByteArray {
            require(array.size <= 0xFFFF) { "\"$field\" array must have no more than $maxLength elements" }
            val out = ByteArray(array.size)
            System.arraycopy(array, 0, out, 0, array.size)
            return out
        }
    }
}
