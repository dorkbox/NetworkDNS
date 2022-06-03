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

import dorkbox.dns.dns.exceptions.NameTooLongException
import dorkbox.dns.dns.exceptions.TextParseException
import dorkbox.dns.dns.exceptions.WireParseException
import dorkbox.dns.dns.records.DNAMERecord
import dorkbox.dns.dns.utils.Options
import java.io.Serializable
import java.text.DecimalFormat

/**
 * A representation of a domain name.  It may either be absolute (fully
 * qualified) or relative.
 *
 * @author Brian Wellington
 */
class Name : Comparable<Name?>, Serializable {
    companion object {
        private const val serialVersionUID = -7257019940971525644L
        private const val LABEL_NORMAL = 0
        private const val LABEL_COMPRESSION = 0xC0
        private const val LABEL_MASK = 0xC0

        private val emptyLabel = byteArrayOf(0.toByte())
        private val wildLabel = byteArrayOf(1.toByte(), '*'.code.toByte())

        /**
         * The root name
         */
        val root = Name()

        /**
         * The root name
         */
        val empty = Name()

        /**
         * The maximum length of a Name
         */
        private const val MAXNAME = 255

        /**
         * The maximum length of a label a Name
         */
        private const val MAXLABEL = 63

        /**
         * The maximum number of labels in a Name
         */
        private const val MAXLABELS = 128

        /**
         * The maximum number of cached offsets
         */
        private const val MAXOFFSETS = 7

        /* Used for printing non-printable characters */
        private val byteFormat = DecimalFormat()

        /* Used to efficiently convert bytes to lowercase */
        private val lowercase = ByteArray(256)

        /* Used in wildcard names. */
        private val wild = Name()

        init {
            byteFormat.minimumIntegerDigits = 3
            for (i in lowercase.indices) {
                if (i < 'A'.code || i > 'Z'.code) {
                    lowercase[i] = i.toByte()
                } else {
                    lowercase[i] = (i - 'A'.code + 'a'.code).toByte()
                }
            }

            root.appendSafe(emptyLabel, 0, 1)
            empty.name = ByteArray(0)
            wild.appendSafe(wildLabel, 0, 1)
        }

        private fun copy(src: Name?, dst: Name) {
            if (src!!.offset(0) == 0) {
                dst.name = src.name
                dst.offsets = src.offsets
            } else {
                val offset0 = src.offset(0)
                val namelen = src.name.size - offset0
                val labels = src.labels()
                dst.name = ByteArray(namelen)
                System.arraycopy(src.name, offset0, dst.name, 0, namelen)
                var i = 0
                while (i < labels && i < MAXOFFSETS) {
                    dst.setoffset(i, src.offset(i) - offset0)
                    i++
                }
                dst.setlabels(labels)
            }
        }
        @Throws(TextParseException::class)
        private fun parseException(str: String, message: String): TextParseException {
            return TextParseException("'$str': $message")
        }

        /**
         * Create a new name from a string and an origin.  This does not automatically
         * make the name absolute; it will be absolute if it has a trailing dot or an
         * absolute origin is appended.  This is identical to the constructor, except
         * that it will avoid creating new objects in some cases.
         *
         * @param s The string to be converted
         * @param origin If the name is not absolute, the origin to be appended.
         *
         * @throws TextParseException The name is invalid.
         */
        @Throws(TextParseException::class)
        fun fromString(s: String, origin: Name? = null): Name {
            if (s == "@" && origin != null) {
                return origin
            } else if (s == ".") {
                return root
            }
            return Name(s, origin)
        }

        /**
         * Create a new name from a constant string.  This should only be used when
         * the name is known to be good - that is, when it is constant.
         *
         * @param s The string to be converted
         *
         * @throws IllegalArgumentException The name is invalid.
         */
        @Throws(IllegalArgumentException::class)
        fun fromConstantString(s: String): Name {
            return try {
                fromString(s, null)
            } catch (e: TextParseException) {
                throw IllegalArgumentException("Invalid name '$s'")
            }
        }

        /**
         * Creates a new name by concatenating two existing names.
         *
         * @param prefix The prefix name.
         * @param suffix The suffix name.
         *
         * @return The concatenated name.
         *
         * @throws NameTooLongException The name is too long.
         */
        @Throws(NameTooLongException::class)
        fun concatenate(prefix: Name, suffix: Name): Name {
            if (prefix.isAbsolute) {
                return prefix
            }
            val newname = Name()
            copy(prefix, newname)
            newname.append(suffix.name, suffix.offset(0), suffix.getlabels())
            return newname
        }
    }

    /**
     * Create a new name from a string and an origin.  This does not automatically
     * make the name absolute; it will be absolute if it has a trailing dot or an
     * absolute origin is appended.
     *
     * @param s The string to be converted
     * @param origin If the name is not absolute, the origin to be appended.
     *
     * @throws TextParseException The name is invalid.
     */
    @Throws(TextParseException::class)
    constructor(s: String, origin: Name? = null) {
        if (s == "") {
            throw parseException(s, "empty name")
        } else if (s == "@") {
            if (origin == null) {
                copy(empty, this)
            } else {
                copy(origin, this)
            }
            return
        } else if (s == ".") {
            copy(root, this)
            return
        }

        var labelstart = -1
        var pos = 1
        val label = ByteArray(MAXLABEL + 1)
        var escaped = false
        var digits = 0
        var intval = 0
        var absolute = false
        for (i in 0 until s.length) {
            var b = s[i].code.toByte()
            if (escaped) {
                if (b >= '0'.code.toByte() && b <= '9'.code.toByte() && digits < 3) {
                    digits++
                    intval *= 10
                    intval += b - '0'.code.toByte()
                    if (intval > 255) {
                        throw parseException(s, "bad escape")
                    }
                    if (digits < 3) {
                        continue
                    }
                    b = intval.toByte()
                } else if (digits > 0 && digits < 3) {
                    throw parseException(s, "bad escape")
                }
                if (pos > MAXLABEL) {
                    throw parseException(s, "label too long")
                }
                labelstart = pos
                label[pos++] = b
                escaped = false
            } else if (b == '\\'.code.toByte()) {
                escaped = true
                digits = 0
                intval = 0
            } else if (b == '.'.code.toByte()) {
                if (labelstart == -1) {
                    throw parseException(s, "invalid empty label")
                }
                label[0] = (pos - 1).toByte()
                appendFromString(s, label, 0, 1)
                labelstart = -1
                pos = 1
            } else {
                if (labelstart == -1) {
                    labelstart = i
                }
                if (pos > MAXLABEL) {
                    throw parseException(s, "label too long")
                }
                label[pos++] = b
            }
        }
        if (digits > 0 && digits < 3) {
            throw parseException(s, "bad escape")
        }
        if (escaped) {
            throw parseException(s, "bad escape")
        }
        if (labelstart == -1) {
            appendFromString(s, emptyLabel, 0, 1)
            absolute = true
        } else {
            label[0] = (pos - 1).toByte()
            appendFromString(s, label, 0, 1)
        }
        if (origin != null && !absolute) {
            appendFromString(s, origin.name, origin.offset(0), origin.getlabels())
        }
    }

    /**
     * Create a new name from DNS a wire format message
     *
     * @param in A stream containing the DNS message which is currently
     * positioned at the start of the name to be read.
     */
    @Throws(WireParseException::class)
    constructor(`in`: DnsInput) {
        var len: Int
        var pos: Int
        var done = false
        val label = ByteArray(MAXLABEL + 1)
        var savedState = false

        while (!done) {
            len = `in`.readU8()
            when (len and LABEL_MASK) {
                LABEL_NORMAL -> {
                    if (getlabels() >= MAXLABELS) {
                        throw WireParseException("too many labels")
                    }
                    if (len == 0) {
                        append(emptyLabel, 0, 1)
                        done = true
                    } else {
                        label[0] = len.toByte()
                        `in`.readByteArray(label, 1, len)
                        append(label, 0, 1)
                    }
                }
                LABEL_COMPRESSION -> {
                    pos = `in`.readU8()
                    pos += len and LABEL_MASK.inv() shl 8
                    if (Options.check("verbosecompression")) {
                        System.err.println("currently " + `in`.readIndex() + ", pointer to " + pos)
                    }
                    if (pos >= `in`.readIndex() - 2) {
                        throw WireParseException("bad compression")
                    }
                    if (!savedState) {
                        `in`.save()
                        savedState = true
                    }
                    `in`.jump(pos)
                    if (Options.check("verbosecompression")) {
                        System.err.println("current name '$this', seeking to $pos")
                    }
                }
                else -> throw WireParseException("bad label type")
            }
        }
        if (savedState) {
            `in`.restore()
        }
    }

    /**
     * Create a new name from DNS wire format
     *
     * @param b A byte array containing the wire format of the name.
     */
    @Throws(WireParseException::class)
    constructor(b: ByteArray) : this(DnsInput(b)) {}

    /**
     * Create a new name by removing labels from the beginning of an existing Name
     *
     * @param src An existing Name
     * @param n The number of labels to remove from the beginning in the copy
     */
    constructor(src: Name, n: Int) {
        val slabels = src.labels()
        require(n <= slabels) { "attempted to remove too " + "many labels" }
        name = src.name
        setlabels(slabels - n)
        var i = 0
        while (i < MAXOFFSETS && i < slabels - n) {
            setoffset(i, src.offset(i + n))
            i++
        }
    }

    /** The name data */
    private var name = ByteArray(0)

    /**
     * Effectively an 8 byte array, where the low order byte stores the number
     * of labels and the 7 higher order bytes store per-label offsets.
     */
    private var offsets: Long = 0

    /* Precomputed hashcode. */
    private var hashcode = 0

    private constructor()

    private fun setoffset(n: Int, offset: Int) {
        if (n >= MAXOFFSETS) {
            return
        }
        val shift = 8 * (7 - n)
        offsets = offsets and (0xFFL shl shift).inv()
        offsets = offsets or (offset.toLong() shl shift)
    }

    private fun offset(n: Int): Int {
        if (n == 0 && getlabels() == 0) {
            return 0
        }
        require(!(n < 0 || n >= getlabels())) { "label out of range" }
        return if (n < MAXOFFSETS) {
            val shift = 8 * (7 - n)
            (offsets ushr shift).toInt() and 0xFF
        } else {
            var pos = offset(MAXOFFSETS - 1)
            for (i in MAXOFFSETS - 1 until n) {
                pos += name[pos] + 1
            }
            pos
        }
    }

    private fun setlabels(labels: Int) {
        offsets = offsets and 0xFF.toLong().inv()
        offsets = offsets or labels.toLong()
    }

    @Throws(NameTooLongException::class)
    private fun append(array: ByteArray, start: Int, n: Int) {
        val length = name.size - offset(0)
        var alength = 0
        run {
            var i = 0
            var pos = start
            while (i < n) {
                var len = array[pos].toInt()
                check(len <= MAXLABEL) { "invalid label" }
                len++
                pos += len
                alength += len
                i++
            }
        }

        val newlength = length + alength
        if (newlength > MAXNAME) {
            throw NameTooLongException()
        }

        val labels = getlabels()
        val newlabels = labels + n
        check(newlabels <= MAXLABELS) { "too many labels" }

        val newname = ByteArray(newlength)
        if (length != 0) {
            System.arraycopy(name, offset(0), newname, 0, length)
        }
        System.arraycopy(array, start, newname, length, alength)
        name = newname

        var i = 0
        var pos = length
        while (i < n) {
            setoffset(labels + i, pos)
            pos += newname[pos] + 1
            i++
        }

        setlabels(newlabels)
    }

    @Throws(TextParseException::class)
    private fun appendFromString(fullName: String, array: ByteArray, start: Int, n: Int) {
        try {
            append(array, start, n)
        } catch (e: NameTooLongException) {
            throw parseException(fullName, "Name too long")
        }
    }

    private fun appendSafe(array: ByteArray, start: Int, n: Int) {
        try {
            append(array, start, n)
        } catch (ignored: NameTooLongException) {
        }
    }

    /**
     * If this name is a subdomain of origin, return a new name relative to
     * origin with the same value. Otherwise, return the existing name.
     *
     * @param origin The origin to remove.
     *
     * @return The possibly relativized name.
     */
    fun relativize(origin: Name?): Name {
        if (origin == null || !subdomain(origin)) {
            return this
        }
        val newname = Name()
        copy(this, newname)
        val length = length() - origin.length()
        val labels = newname.labels() - origin.labels()
        newname.setlabels(labels)
        newname.name = ByteArray(length)
        System.arraycopy(name, offset(0), newname.name, 0, length)
        return newname
    }

    /**
     * Generates a new Name with the first n labels are removed
     *
     * @return The parent name
     */
    fun parent(n: Int): Name {
        require(n >= 1) { "must remove 1 or more " + "labels" }

        return try {
            val newname = Name()
            newname.append(name, offset(n), getlabels() - n)
            newname
        } catch (e: NameTooLongException) {
            throw IllegalStateException("Name.subdomain: concatenate failed")
        }
    }

    /**
     * Generates a new Name with the first n labels replaced by a wildcard
     *
     * @return The wildcard name
     */
    fun wild(n: Int): Name {
        require(n >= 1) { "must replace 1 or more " + "labels" }

        return try {
            val newname = Name()
            copy(wild, newname)
            newname.append(name, offset(n), getlabels() - n)
            newname
        } catch (e: NameTooLongException) {
            throw IllegalStateException("Name.wild: concatenate failed")
        }
    }

    /**
     * Returns a canonicalized version of the Name (all lowercase).  This may be
     * the same name, if the input Name is already canonical.
     */
    fun canonicalize(): Name {
        var canonical = true
        for (i in name.indices) {
            if (lowercase[name[i].toInt() and 0xFF] != name[i]) {
                canonical = false
                break
            }
        }
        if (canonical) {
            return this
        }

        val newname = Name()
        newname.appendSafe(name, offset(0), getlabels())
        for (i in newname.name.indices) {
            newname.name[i] = lowercase[newname.name[i].toInt() and 0xFF]
        }

        return newname
    }

    /**
     * Generates a new Name to be used when following a DNAME.
     *
     * @param dname The DNAME record to follow.
     *
     * @return The constructed name.
     *
     * @throws NameTooLongException The resulting name is too long.
     */
    @Throws(NameTooLongException::class)
    fun fromDNAME(dname: DNAMERecord): Name? {
        val dnameowner = dname.name
        val dnametarget = dname.target
        if (!subdomain(dnameowner)) {
            return null
        }

        val plabels = labels() - dnameowner.labels()
        val plength = length() - dnameowner.length()
        val pstart = offset(0)
        val dlabels = dnametarget.labels()
        val dlength = dnametarget.length().toInt()

        if (plength + dlength > MAXNAME) {
            throw NameTooLongException()
        }

        val newname = Name()
        newname.setlabels(plabels + dlabels)
        newname.name = ByteArray(plength + dlength)
        System.arraycopy(name, pstart, newname.name, 0, plength)
        System.arraycopy(dnametarget.name, 0, newname.name, plength, dlength)

        var i = 0
        var pos = 0
        while (i < MAXOFFSETS && i < plabels + dlabels) {
            newname.setoffset(i, pos)
            pos += newname.name[pos] + 1
            i++
        }
        return newname
    }

    /**
     * Is this name a wildcard?
     */
    val isWild: Boolean
        get() = if (labels() == 0) {
            false
        } else name[0] == 1.toByte() && name[1] == '*'.code.toByte()

    /**
     * The number of labels in the name.
     */
    fun labels(): Int {
        return getlabels()
    }

    private fun getlabels(): Int {
        return (offsets and 0xFFL).toInt()
    }

    /**
     * Is this name absolute?
     */
    val isAbsolute: Boolean
        get() {
            val nlabels = labels()
            return if (nlabels == 0) {
                false
            } else name[offset(nlabels - 1)].toInt() == 0
        }

    /**
     * The length of the name.
     */
    fun length(): Short {
        return if (getlabels() == 0) {
            0
        } else (name.size - offset(0)).toShort()
    }

    /**
     * Is the current Name a subdomain of the specified name?
     */
    fun subdomain(domain: Name): Boolean {
        val labels = labels()
        val dlabels = domain.labels()
        if (dlabels > labels) {
            return false
        }
        return if (dlabels == labels) {
            equals(domain)
        } else domain.equals(name, offset(labels - dlabels))
    }

    private fun byteString(array: ByteArray, pos: Int): String {
        var pos = pos
        val sb = StringBuilder()
        val len = array[pos++].toInt()
        for (i in pos until pos + len) {
            val b = array[i].toInt() and 0xFF
            if (b <= 0x20 || b >= 0x7f) {
                sb.append('\\')
                sb.append(byteFormat.format(b.toLong()))
            } else if (b == '"'.code || b == '('.code || b == ')'.code || b == '.'.code || b == ';'.code || b == '\\'.code || b == '@'.code || b == '$'.code) {
                sb.append('\\')
                sb.append(b.toChar())
            } else {
                sb.append(b.toChar())
            }
        }
        return sb.toString()
    }

    /**
     * Convert a Name to a String
     *
     * @param omitFinalDot If true, and the name is absolute, omit the final dot.
     *
     * @return The representation of this name as a (printable) String.
     */
    fun toString(omitFinalDot: Boolean): String {
        val labels = labels()
        if (labels == 0) {
            return "@"
        } else if (labels == 1 && name[offset(0)].toInt() == 0) {
            return "."
        }
        val sb = StringBuilder()

        var i = 0
        var pos = offset(0)
        while (i < labels) {
            val len = name[pos].toInt()
            check(len <= MAXLABEL) { "invalid label" }
            if (len == 0) {
                if (!omitFinalDot) {
                    sb.append('.')
                }
                break
            }
            if (i > 0) {
                sb.append('.')
            }
            sb.append(byteString(name, pos))
            pos += 1 + len
            i++
        }
        return sb.toString()
    }

    /**
     * Retrieve the nth label of a Name.  This makes a copy of the label; changing
     * this does not change the Name.
     *
     * @param n The label to be retrieved.  The first label is 0.
     */
    fun getLabel(n: Int): ByteArray {
        val pos = offset(n)
        val len = (name[pos] + 1).toByte()
        val label = ByteArray(len.toInt())
        System.arraycopy(name, pos, label, 0, len.toInt())
        return label
    }

    /**
     * Convert the nth label in a Name to a String
     *
     * @param n The label to be converted to a (printable) String.  The first
     * label is 0.
     */
    fun getLabelString(n: Int): String {
        val pos = offset(n)
        return byteString(name, pos)
    }

    /**
     * Emit a Name in DNS wire format
     *
     * @param out The output stream containing the DNS message.
     * @param c The compression context, or null of no compression is desired.
     *
     * @throws IllegalArgumentException The name is not absolute.
     */
    @kotlin.jvm.Throws(IllegalArgumentException::class)
    fun toWire(out: DnsOutput, c: Compression?) {
        require(isAbsolute) { "toWire() called on " + "non-absolute name" }

        val labels = labels()
        for (i in 0 until labels - 1) {
            var tname: Name
            tname = if (i == 0) {
                this
            } else {
                Name(this, i)
            }
            var pos = -1
            if (c != null) {
                pos = c[tname]
            }
            if (pos >= 0) {
                pos = pos or (LABEL_MASK shl 8)
                out.writeU16(pos)
                return
            } else {
                c?.add(out.current(), tname)
                val off = offset(i)
                out.writeByteArray(name, off, name[off] + 1)
            }
        }
        out.writeU8(0)
    }

    /**
     * Emit a Name in DNS wire format
     *
     * @throws IllegalArgumentException The name is not absolute.
     */
    fun toWire(): ByteArray {
        val out = DnsOutput()
        toWire(out, null)
        return out.toByteArray()
    }

    /**
     * Emit a Name in canonical DNS wire format (all lowercase)
     *
     * @param out The output stream to which the message is written.
     */
    fun toWireCanonical(out: DnsOutput) {
        val b = toWireCanonical()
        out.writeByteArray(b)
    }

    /**
     * Emit a Name in canonical DNS wire format (all lowercase)
     *
     * @return The canonical form of the name.
     */
    fun toWireCanonical(): ByteArray {
        val labels = labels()
        if (labels == 0) {
            return ByteArray(0)
        }
        val b = ByteArray(name.size - offset(0))
        var i = 0
        var spos = offset(0)
        var dpos = 0
        while (i < labels) {
            val len = name[spos].toInt()
            check(len <= MAXLABEL) { "invalid label" }
            b[dpos++] = name[spos++]
            for (j in 0 until len) {
                b[dpos++] = lowercase[name[spos++].toInt() and 0xFF]
            }
            i++
        }
        return b
    }

    /**
     * Emit a Name in DNS wire format
     *
     * @param out The output stream containing the DNS message.
     * @param c The compression context, or null of no compression is desired.
     * @param canonical If true, emit the name in canonicalized form
     * (all lowercase).
     *
     * @throws IllegalArgumentException The name is not absolute.
     */
    fun toWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        if (canonical) {
            toWireCanonical(out)
        } else {
            toWire(out, c)
        }
    }

    private fun equals(b: ByteArray?, bpos: Int): Boolean {
        var bpos = bpos
        val labels = labels()
        var i = 0
        var pos = offset(0)
        while (i < labels) {
            if (name[pos] != b!![bpos]) {
                return false
            }
            val len = name[pos++].toInt()
            bpos++
            check(len <= MAXLABEL) { "invalid label" }
            for (j in 0 until len) {
                if (lowercase[name[pos++].toInt() and 0xFF] != lowercase[b[bpos++].toInt() and 0xFF]) {
                    return false
                }
            }
            i++
        }
        return true
    }

    /**
     * Computes a hashcode based on the value
     */
    override fun hashCode(): Int {
        if (hashcode != 0) {
            return hashcode
        }
        var code = 0
        for (i in offset(0) until name.size) {
            code += ((code shl 3) + lowercase[name[i].toInt() and 0xFF])
        }
        hashcode = code
        return hashcode
    }

    /**
     * Are these two Names equivalent?
     */
    override fun equals(other: Any?): Boolean {
        if (other === this) {
            return true
        }
        if (other == null || other !is Name) {
            return false
        }

        if (other.hashcode == 0) {
            other.hashCode()
        }

        if (hashcode == 0) {
            hashCode()
        }

        if (other.hashcode != hashcode) {
            return false
        }

        if (other.labels() != labels()) {
            return false
        }

        return equals(other.name, other.offset(0))
    }

    /**
     * Convert a Name to a String
     *
     * @return The representation of this name as a (printable) String.
     */
    override fun toString(): String {
        return toString(false)
    }

    /**
     * Compares this Name to another Object.
     *
     * @param other The Object to be compared.
     *
     * @return The value 0 if the argument is a name equivalent to this name;
     * a value less than 0 if the argument is less than this name in the canonical
     * ordering, and a value greater than 0 if the argument is greater than this
     * name in the canonical ordering.
     *
     * @throws ClassCastException if the argument is not a Name.
     */
    override fun compareTo(other: Name?): Int {
        if (this === other) {
            return 0
        }

        if (other == null) {
            return -1
        }

        val arg = other

        val labels = labels()
        val alabels = arg.labels()
        val compares = if (labels > alabels) alabels else labels

        for (i in 1..compares) {
            val start = offset(labels - i)
            val astart = arg.offset(alabels - i)
            val length = name[start].toInt()
            val alength = arg.name[astart].toInt()

            var j = 0
            while (j < length && j < alength) {
                val n = lowercase[name[j + start + 1].toInt() and 0xFF] - lowercase[arg.name[j + astart + 1].toInt() and 0xFF]
                if (n != 0) {
                    return n
                }
                j++
            }

            if (length != alength) {
                return length - alength
            }
        }

        return labels - alabels
    }
}
