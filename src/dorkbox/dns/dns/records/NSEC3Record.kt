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
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.utils.Tokenizer
import dorkbox.dns.dns.utils.base16.toString
import dorkbox.dns.dns.utils.base32
import java.io.IOException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

/**
 * Next SECure name 3 - this record contains the next hashed name in an
 * ordered list of hashed names in the zone, and a set of types for which
 * records exist for this name. The presence of this record in a response
 * signifies a negative response from a DNSSEC-signed zone.
 *
 *
 * This replaces the NSEC and NXT records, when used.
 *
 * @author Brian Wellington
 * @author David Blacka
 */
class NSEC3Record : DnsRecord {
    /**
     * Returns the hash algorithm
     */
    var hashAlgorithm = 0
        private set

    /**
     * Returns the flags
     */
    var flags = 0
        private set

    /**
     * Returns the number of iterations
     */
    var iterations = 0
        private set

    /**
     * Returns the salt
     */
    var salt: ByteArray? = null
        private set

    /**
     * Returns the next hash
     */
    lateinit var next: ByteArray
        private set


    private var types: TypeBitmap? = null

    object Flags {
        /**
         * Unsigned delegation are not included in the NSEC3 chain.
         */
        const val OPT_OUT = 0x01
    }

    object Digest {
        /**
         * SHA-1
         */
        const val SHA1 = 1
    }

    internal constructor() {}

    override val `object`: DnsRecord
        get() = NSEC3Record()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        hashAlgorithm = `in`.readU8()
        flags = `in`.readU8()
        iterations = `in`.readU16()
        val salt_length = `in`.readU8()
        salt = if (salt_length > 0) {
            `in`.readByteArray(salt_length)
        } else {
            null
        }
        val next_length = `in`.readU8()
        next = `in`.readByteArray(next_length)
        types = TypeBitmap(`in`)
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeU8(hashAlgorithm)
        out.writeU8(flags)
        out.writeU16(iterations)
        if (salt != null) {
            out.writeU8(salt!!.size)
            out.writeByteArray(salt!!)
        } else {
            out.writeU8(0)
        }
        out.writeU8(next.size)
        out.writeByteArray(next)
        types!!.toWire(out)
    }

    /**
     * Converts rdata to a String
     */
    override fun rrToString(sb: StringBuilder) {
        sb.append(hashAlgorithm)
        sb.append(' ')
        sb.append(flags)
        sb.append(' ')
        sb.append(iterations)
        sb.append(' ')
        if (salt == null) {
            sb.append('-')
        } else {
            sb.append(toString(salt!!))
        }
        sb.append(' ')
        sb.append(b32.toString(next))
        if (!types!!.empty()) {
            sb.append(' ')
            sb.append(types.toString())
        }
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        hashAlgorithm = st.getUInt8()
        flags = st.getUInt8()
        iterations = st.getUInt16()
        val s = st.getString()
        if (s == "-") {
            salt = null
        } else {
            st.unget()
            salt = st.hexString
            if (salt!!.size > 255) {
                throw st.exception("salt value too long")
            }
        }
        next = st.getBase32String(b32)
        types = TypeBitmap(st)
    }

    /**
     * Creates an NSEC3 record from the given data.
     *
     * @param name The ownername of the NSEC3 record (base32'd hash plus zonename).
     * @param dclass The class.
     * @param ttl The TTL.
     * @param hashAlg The hash algorithm.
     * @param flags The value of the flags field.
     * @param iterations The number of hash iterations.
     * @param salt The salt to use (may be null).
     * @param next The next hash (may not be null).
     * @param types The types present at the original ownername.
     */
    constructor(
        name: Name?,
        dclass: Int,
        ttl: Long,
        hashAlg: Int,
        flags: Int,
        iterations: Int,
        salt: ByteArray?,
        next: ByteArray,
        types: IntArray
    ) : super(
        name!!, DnsRecordType.NSEC3, dclass, ttl
    ) {
        hashAlgorithm = checkU8("hashAlg", hashAlg)
        this.flags = checkU8("flags", flags)
        this.iterations = checkU16("iterations", iterations)

        if (salt != null) {
            require(salt.size <= 255) { "Invalid salt" }
            if (salt.size > 0) {
                this.salt = ByteArray(salt.size)
                System.arraycopy(salt, 0, this.salt, 0, salt.size)
            }
        }
        require(next.size <= 255) { "Invalid next hash" }

        this.next = ByteArray(next.size)
        System.arraycopy(next, 0, this.next, 0, next.size)
        this.types = TypeBitmap(types)
    }

    /**
     * Returns the set of types defined for this name
     */
    fun getTypes(): IntArray {
        return types!!.toArray()
    }

    /**
     * Returns whether a specific type is in the set of types.
     */
    fun hasType(type: Int): Boolean {
        return types!!.contains(type)
    }

    /**
     * Hashes a name with the parameters of this NSEC3 record.
     *
     * @param name The name to hash
     *
     * @return The hashed version of the name
     *
     * @throws NoSuchAlgorithmException The hash algorithm is unknown.
     */
    @Throws(NoSuchAlgorithmException::class)
    fun hashName(name: Name): ByteArray? {
        return hashName(name, hashAlgorithm, iterations, salt)
    }

    companion object {
        const val SHA1_DIGEST_ID = Digest.SHA1
        private const val serialVersionUID = -7123504635968932855L
        private val b32 = base32(base32.Alphabet.BASE32HEX, false, false)
        @Throws(NoSuchAlgorithmException::class)
        fun hashName(name: Name, hashAlg: Int, iterations: Int, salt: ByteArray?): ByteArray? {
            val digest: MessageDigest
            digest = when (hashAlg) {
                Digest.SHA1 -> MessageDigest.getInstance("sha-1")
                else -> throw NoSuchAlgorithmException("Unknown NSEC3 algorithmidentifier: $hashAlg")
            }
            var hash: ByteArray? = null
            for (i in 0..iterations) {
                digest.reset()
                if (i == 0) {
                    digest.update(name.toWireCanonical())
                } else {
                    digest.update(hash)
                }
                if (salt != null) {
                    digest.update(salt)
                }
                hash = digest.digest()
            }
            return hash
        }
    }
}
