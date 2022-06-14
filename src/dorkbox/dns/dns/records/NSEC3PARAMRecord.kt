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
import java.io.IOException
import java.security.NoSuchAlgorithmException

/**
 * Next SECure name 3 Parameters - this record contains the parameters (hash
 * algorithm, salt, iterations) used for a valid, complete NSEC3 chain present
 * in a zone. Zones signed using NSEC3 must include this record at the zone apex
 * to inform authoritative servers that NSEC3 is being used with the given
 * parameters.
 *
 * @author Brian Wellington
 * @author David Blacka
 */
class NSEC3PARAMRecord : DnsRecord {
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

    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = NSEC3PARAMRecord()

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
    }

    /**
     * Creates an NSEC3PARAM record from the given data.
     *
     * @param name The ownername of the NSEC3PARAM record (generally the zone name).
     * @param dclass The class.
     * @param ttl The TTL.
     * @param hashAlg The hash algorithm.
     * @param flags The value of the flags field.
     * @param iterations The number of hash iterations.
     * @param salt The salt to use (may be null).
     */
    constructor(name: Name?, dclass: Int, ttl: Long, hashAlg: Int, flags: Int, iterations: Int, salt: ByteArray?) : super(
        name!!, DnsRecordType.NSEC3PARAM, dclass, ttl
    ) {
        hashAlgorithm = checkU8("hashAlg", hashAlg)
        this.flags = checkU8("flags", flags)
        this.iterations = checkU16("iterations", iterations)
        if (salt != null) {
            require(salt.size <= 255) { "Invalid salt " + "length" }
            if (salt.size > 0) {
                this.salt = ByteArray(salt.size)
                System.arraycopy(salt, 0, this.salt, 0, salt.size)
            }
        }
    }

    /**
     * Hashes a name with the parameters of this NSEC3PARAM record.
     *
     * @param name The name to hash
     *
     * @return The hashed version of the name
     *
     * @throws NoSuchAlgorithmException The hash algorithm is unknown.
     */
    @Throws(NoSuchAlgorithmException::class)
    fun hashName(name: Name): ByteArray? {
        return NSEC3Record.hashName(name, hashAlgorithm, iterations, salt)
    }

    companion object {
        private const val serialVersionUID = -8689038598776316533L
    }
}
