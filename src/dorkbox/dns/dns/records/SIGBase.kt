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
import dorkbox.dns.dns.constants.DnsRecordType.check
import dorkbox.dns.dns.constants.DnsRecordType.string
import dorkbox.dns.dns.constants.DnsRecordType.value
import dorkbox.dns.dns.utils.FormattedTime.format
import dorkbox.dns.dns.utils.FormattedTime.parse
import dorkbox.dns.dns.utils.Options.check
import dorkbox.dns.dns.utils.Tokenizer
import dorkbox.os.OS.LINE_SEPARATOR
import java.io.IOException
import java.util.*

/**
 * The base class for SIG/RRSIG records, which have identical formats
 *
 * @author Brian Wellington
 */
abstract class SIGBase : DnsRecord {
    /**
     * Returns the RRset type covered by this signature
     */
    var typeCovered = 0
        protected set

    /**
     * Returns the cryptographic algorithm of the key that generated the signature
     */
    var algorithm = 0
        protected set

    /**
     * Returns the number of labels in the signed domain name.  This may be
     * different than the record's domain name if the record is a wildcard
     * record.
     */
    var labels = 0
        protected set

    /**
     * Returns the original TTL of the RRset
     */
    var origTTL: Long = 0
        protected set

    /**
     * Returns the time at which the signature expires
     */
    var expire: Date
        protected set

    /**
     * Returns the time at which this signature was generated
     */
    var timeSigned: Date
        protected set

    /**
     * Returns The footprint/key id of the signing key.
     */
    var footprint = 0
        protected set

    /**
     * Returns the owner of the signing key
     */
    var signer: Name
        protected set

    /**
     * Returns the binary data representing the signature
     */
    var signature: ByteArray

    protected constructor() : this(
        Name.empty, DnsRecordType.A, DnsClass.ANY, 0L, DnsRecordType.A, 0, 0, Date(), Date(), 0, Name.root, byteArrayOf()
    )
    constructor(
        name: Name,
        type: Int,
        dclass: Int,
        ttl: Long,
        covered: Int,
        alg: Int,
        origttl: Long,
        expire: Date,
        timeSigned: Date,
        footprint: Int,
        signer: Name,
        signature: ByteArray
    ) : super(name, type, dclass, ttl) {
        check(covered)
        TTL.check(origttl)
        typeCovered = covered
        algorithm = checkU8("alg", alg)
        labels = name.labels() - 1
        if (name.isWild) {
            labels--
        }

        origTTL = origttl
        this.expire = expire
        this.timeSigned = timeSigned
        this.footprint = checkU16("footprint", footprint)
        this.signer = checkName("signer", signer)
        this.signature = signature
    }

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        typeCovered = `in`.readU16()
        algorithm = `in`.readU8()
        labels = `in`.readU8()
        origTTL = `in`.readU32()
        expire = Date(1000 * `in`.readU32())
        timeSigned = Date(1000 * `in`.readU32())
        footprint = `in`.readU16()
        signer = Name(`in`)
        signature = `in`.readByteArray()
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeU16(typeCovered)
        out.writeU8(algorithm)
        out.writeU8(labels)
        out.writeU32(origTTL)
        out.writeU32(expire.time / 1000)
        out.writeU32(timeSigned.time / 1000)
        out.writeU16(footprint)
        signer.toWire(out, null, canonical)
        out.writeByteArray(signature)
    }

    /**
     * Converts the RRSIG/SIG Record to a String
     */
    override fun rrToString(sb: StringBuilder) {
        sb.append(string(typeCovered))
        sb.append(" ")
        sb.append(algorithm)
        sb.append(" ")
        sb.append(labels)
        sb.append(" ")
        sb.append(origTTL)
        sb.append(" ")
        if (check("multiline")) {
            sb.append("(")
            sb.append(LINE_SEPARATOR)
            sb.append("\t")
        }
        sb.append(format(expire))
        sb.append(" ")
        sb.append(format(timeSigned))
        sb.append(" ")
        sb.append(footprint)
        sb.append(" ")
        sb.append(signer)
        if (check("multiline")) {
            sb.append(LINE_SEPARATOR)
            sb.append(Base64.getEncoder().encodeToString(signature))
        } else {
            sb.append(" ")
            sb.append(Base64.getMimeEncoder().encodeToString(signature))
        }
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        val typeString = st.getString()
        typeCovered = value(typeString)
        if (typeCovered < 0) {
            throw st.exception("Invalid type: $typeString")
        }
        val algString = st.getString()
        algorithm = DNSSEC.Algorithm.value(algString)
        if (algorithm < 0) {
            throw st.exception("Invalid algorithm: $algString")
        }
        labels = st.getUInt8()
        origTTL = st.getTTL()
        expire = parse(st.getString())
        timeSigned = parse(st.getString())
        footprint = st.getUInt16()
        signer = st.getName(origin)
        signature = st.getBase64(true)!!
    }

    companion object {
        private const val serialVersionUID = -3738444391533812369L
    }
}
