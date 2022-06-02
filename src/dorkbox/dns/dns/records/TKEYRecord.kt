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
import dorkbox.dns.dns.constants.DnsResponseCode.TSIGstring
import dorkbox.dns.dns.utils.FormattedTime.format
import dorkbox.dns.dns.utils.Options.check
import dorkbox.dns.dns.utils.Tokenizer
import dorkbox.os.OS.LINE_SEPARATOR
import java.io.IOException
import java.util.*

/**
 * Transaction Key - used to compute and/or securely transport a shared
 * secret to be used with TSIG.
 *
 * @author Brian Wellington
 * @see TSIG
 */
class TKEYRecord : DnsRecord {
    /**
     * Returns the shared key's algorithm
     */
    var algorithm: Name? = null
        private set

    /**
     * Returns the beginning of the validity period of the shared secret or
     * keying material
     */
    var timeInception: Date? = null
        private set

    /**
     * Returns the end of the validity period of the shared secret or
     * keying material
     */
    var timeExpire: Date? = null
        private set

    /**
     * Returns the key agreement mode
     */
    var mode = 0
        private set

    /**
     * Returns the extended error
     */
    var error = 0
        private set

    /**
     * Returns the shared secret or keying material
     */
    var key: ByteArray? = null
        private set

    /**
     * Returns the other data
     */
    var other: ByteArray? = null
        private set

    internal constructor() {}

    override val `object`: DnsRecord
        get() = TKEYRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        algorithm = Name(`in`)
        timeInception = Date(1000 * `in`.readU32())
        timeExpire = Date(1000 * `in`.readU32())
        mode = `in`.readU16()
        error = `in`.readU16()
        val keylen = `in`.readU16()
        key = if (keylen > 0) {
            `in`.readByteArray(keylen)
        } else {
            null
        }
        val otherlen = `in`.readU16()
        other = if (otherlen > 0) {
            `in`.readByteArray(otherlen)
        } else {
            null
        }
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        algorithm!!.toWire(out, null, canonical)
        out.writeU32(timeInception!!.time / 1000)
        out.writeU32(timeExpire!!.time / 1000)
        out.writeU16(mode)
        out.writeU16(error)
        if (key != null) {
            out.writeU16(key!!.size)
            out.writeByteArray(key!!)
        } else {
            out.writeU16(0)
        }
        if (other != null) {
            out.writeU16(other!!.size)
            out.writeByteArray(other!!)
        } else {
            out.writeU16(0)
        }
    }

    /**
     * Converts rdata to a String
     */
    override fun rrToString(sb: StringBuilder) {
        sb.append(algorithm)
        sb.append(" ")
        if (check("multiline")) {
            sb.append("(").append(LINE_SEPARATOR).append("\t")
        }
        sb.append(format(timeInception))
        sb.append(" ")
        sb.append(format(timeExpire))
        sb.append(" ")
        sb.append(modeString())
        sb.append(" ")
        sb.append(TSIGstring(error))
        if (check("multiline")) {
            sb.append(LINE_SEPARATOR)
            if (key != null) {
                sb.append(Base64.getMimeEncoder().encodeToString(key))
                sb.append(LINE_SEPARATOR)
            }
            if (other != null) {
                sb.append(Base64.getMimeEncoder().encodeToString(other))
            }
            sb.append(" )")
        } else {
            sb.append(" ")
            if (key != null) {
                sb.append("\t")
                sb.append(Base64.getEncoder().encodeToString(key))
                sb.append(" ")
            }
            if (other != null) {
                sb.append("\t")
                sb.append(Base64.getEncoder().encodeToString(other))
            }
        }
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        throw st.exception("no text format defined for TKEY")
    }

    protected fun modeString(): String {
        return when (mode) {
            SERVERASSIGNED -> "SERVERASSIGNED"
            DIFFIEHELLMAN -> "DIFFIEHELLMAN"
            GSSAPI -> "GSSAPI"
            RESOLVERASSIGNED -> "RESOLVERASSIGNED"
            DELETE -> "DELETE"
            else -> Integer.toString(mode)
        }
    }

    /**
     * Creates a TKEY Record from the given data.
     *
     * @param alg The shared key's algorithm
     * @param timeInception The beginning of the validity period of the shared
     * secret or keying material
     * @param timeExpire The end of the validity period of the shared
     * secret or keying material
     * @param mode The mode of key agreement
     * @param error The extended error field.  Should be 0 in queries
     * @param key The shared secret
     * @param other The other data field.  Currently unused
     * responses.
     */
    constructor(
        name: Name?,
        dclass: Int,
        ttl: Long,
        alg: Name?,
        timeInception: Date?,
        timeExpire: Date?,
        mode: Int,
        error: Int,
        key: ByteArray?,
        other: ByteArray?
    ) : super(name!!, DnsRecordType.TKEY, dclass, ttl) {
        algorithm = checkName("alg", alg!!)
        this.timeInception = timeInception
        this.timeExpire = timeExpire
        this.mode = checkU16("mode", mode)
        this.error = checkU16("error", error)
        this.key = key
        this.other = other
    }

    companion object {
        private const val serialVersionUID = 8828458121926391756L

        /**
         * The key is assigned by the server (unimplemented)
         */
        const val SERVERASSIGNED = 1

        /**
         * The key is computed using a Diffie-Hellman key exchange
         */
        const val DIFFIEHELLMAN = 2

        /**
         * The key is computed using GSS_API (unimplemented)
         */
        const val GSSAPI = 3

        /**
         * The key is assigned by the resolver (unimplemented)
         */
        const val RESOLVERASSIGNED = 4

        /**
         * The key should be deleted
         */
        const val DELETE = 5
    }
}
