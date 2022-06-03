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

import dorkbox.collections.ObjectMap
import dorkbox.dns.dns.DnsOutput
import dorkbox.dns.dns.Name
import dorkbox.dns.dns.constants.DnsClass
import dorkbox.dns.dns.constants.DnsResponseCode
import dorkbox.dns.dns.constants.DnsSection
import dorkbox.dns.dns.exceptions.TextParseException
import dorkbox.dns.dns.utils.Options.check
import dorkbox.dns.dns.utils.Options.intValue
import java.security.GeneralSecurityException
import java.util.*
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * Transaction signature handling.  This class generates and verifies
 * TSIG records on messages, which provide transaction security.
 *
 * @author Brian Wellington
 * @see TSIGRecord
 */
class TSIG {
    private var name: Name
    private var alg: Name
    private var hmac: Mac? = null

    /**
     * Creates a new TSIG key, which can be used to sign or verify a message.
     *
     * @param algorithm The algorithm of the shared key.
     * @param name The name of the shared key.
     * @param key The shared key.
     */
    constructor(algorithm: Name, name: Name, key: SecretKey) {
        this.name = name
        alg = algorithm
        val macAlgorithm = nameToAlgorithm(algorithm)
        init_hmac(macAlgorithm, key)
    }

    private fun init_hmac(macAlgorithm: String, key: SecretKey) {
        try {
            hmac = Mac.getInstance(macAlgorithm)
            hmac!!.init(key)
        } catch (ex: GeneralSecurityException) {
            throw IllegalArgumentException("Caught security " + "exception setting up " + "HMAC.")
        }
    }

    /**
     * Creates a new TSIG key from a pre-initialized Mac instance.
     * This assumes that init() has already been called on the mac
     * to set up the key.
     *
     * @param mac The JCE HMAC object
     * @param name The name of the key
     */
    constructor(mac: Mac, name: Name) {
        this.name = name
        hmac = mac
        alg = algorithmToName(mac.algorithm)
    }

    /**
     * Creates a new TSIG key with the hmac-md5 algorithm, which can be used to
     * sign or verify a message.
     *
     * @param name The name of the shared key.
     * @param key The shared key's data.
     */
    constructor(name: Name, key: ByteArray) : this(HMAC_MD5, name, key) {}

    /**
     * Creates a new TSIG key, which can be used to sign or verify a message.
     *
     * @param algorithm The algorithm of the shared key.
     * @param name The name of the shared key.
     * @param keyBytes The shared key's data.
     */
    constructor(algorithm: Name, name: Name, keyBytes: ByteArray) {
        this.name = name
        alg = algorithm
        val macAlgorithm = nameToAlgorithm(algorithm)
        val key: SecretKey = SecretKeySpec(keyBytes, macAlgorithm)
        init_hmac(macAlgorithm, key)
    }

    /**
     * Creates a new TSIG object, which can be used to sign or verify a message.
     *
     * @param name The name of the shared key.
     * @param algorithm The algorithm of the shared key.  The legal values are
     * "hmac-md5", "hmac-sha1", "hmac-sha224", "hmac-sha256", "hmac-sha384", and
     * "hmac-sha512".
     * @param key The shared key's data represented as a base64 encoded string.
     *
     * @throws IllegalArgumentException The key name is an invalid name
     * @throws IllegalArgumentException The key data is improperly encoded
     */
    constructor(algorithm: String, name: String, key: String) : this(algorithmToName(algorithm), name, key) {}

    /**
     * Creates a new TSIG object, which can be used to sign or verify a message.
     *
     * @param name The name of the shared key.
     * @param key The shared key's data represented as a base64 encoded string.
     *
     * @throws IllegalArgumentException The key name is an invalid name
     * @throws IllegalArgumentException The key data is improperly encoded
     */
    constructor(algorithm: Name, name: String, key: String) {
        val keyBytes = Base64.getDecoder().decode(key)
        require(keyBytes.size != 0) { "Invalid TSIG key string" }

        try {
            this.name = Name.Companion.fromString(name, Name.root)
        } catch (e: TextParseException) {
            throw IllegalArgumentException("Invalid TSIG key name")
        }

        alg = algorithm
        val macAlgorithm = nameToAlgorithm(alg)
        init_hmac(macAlgorithm, SecretKeySpec(keyBytes, macAlgorithm))
    }

    /**
     * Creates a new TSIG object with the hmac-md5 algorithm, which can be used to
     * sign or verify a message.
     *
     * @param name The name of the shared key
     * @param key The shared key's data, represented as a base64 encoded string.
     *
     * @throws IllegalArgumentException The key name is an invalid name
     * @throws IllegalArgumentException The key data is improperly encoded
     */
    constructor(name: String, key: String) : this(HMAC_MD5, name, key) {}

    /**
     * Generates a TSIG record for a message and adds it to the message
     *
     * @param m The message
     * @param old If this message is a response, the TSIG from the request
     */
    fun applyStream(m: DnsMessage, old: TSIGRecord, first: Boolean) {
        if (first) {
            apply(m, old)
            return
        }
        val timeSigned = Date()
        var fudge: Int
        hmac!!.reset()
        fudge = intValue("tsigfudge")
        if (fudge < 0 || fudge > 0x7FFF) {
            fudge = FUDGE.toInt()
        }
        var out = DnsOutput()
        out.writeU16(old.signature.size)
        hmac!!.update(out.toByteArray())
        hmac!!.update(old.signature)

        /* Digest the message */hmac!!.update(m.toWire())
        out = DnsOutput()
        val time = timeSigned.time / 1000
        val timeHigh = (time shr 32).toInt()
        val timeLow = time and 0xFFFFFFFFL
        out.writeU16(timeHigh)
        out.writeU32(timeLow)
        out.writeU16(fudge)
        hmac!!.update(out.toByteArray())
        val signature = hmac!!.doFinal()
        val other: ByteArray? = null
        val r: DnsRecord = TSIGRecord(
            name, DnsClass.ANY, 0, alg, timeSigned, fudge, signature, m.header.iD, DnsResponseCode.NOERROR, other
        )
        m.addRecord(r, DnsSection.ADDITIONAL)
        m.tsigState = DnsMessage.TSIG_SIGNED
    }

    /**
     * Generates a TSIG record for a message and adds it to the message
     *
     * @param m The message
     * @param old If this message is a response, the TSIG from the request
     */
    fun apply(m: DnsMessage, old: TSIGRecord?) {
        apply(m, DnsResponseCode.NOERROR, old)
    }

    /**
     * Generates a TSIG record with a specific error for a message and adds it
     * to the message.
     *
     * @param m The message
     * @param error The error
     * @param old If this message is a response, the TSIG from the request
     */
    fun apply(m: DnsMessage, error: Int, old: TSIGRecord?) {
        val r: DnsRecord = generate(m, m.toWire(), error, old)
        m.addRecord(r, DnsSection.ADDITIONAL)
        m.tsigState = DnsMessage.TSIG_SIGNED
    }

    /**
     * Generates a TSIG record with a specific error for a message that has
     * been rendered.
     *
     * @param m The message
     * @param b The rendered message
     * @param error The error
     * @param old If this message is a response, the TSIG from the request
     *
     * @return The TSIG record to be added to the message
     */
    fun generate(m: DnsMessage, b: ByteArray?, error: Int, old: TSIGRecord?): TSIGRecord {
        val timeSigned: Date
        timeSigned = if (error != DnsResponseCode.BADTIME) {
            Date()
        } else {
            old!!.timeSigned
        }
        var fudge: Int
        var signing = false
        if (error == DnsResponseCode.NOERROR || error == DnsResponseCode.BADTIME) {
            signing = true
            hmac!!.reset()
        }
        fudge = intValue("tsigfudge")
        if (fudge < 0 || fudge > 0x7FFF) {
            fudge = FUDGE.toInt()
        }
        if (old != null) {
            val out = DnsOutput()
            out.writeU16(old.signature.size)
            if (signing) {
                hmac!!.update(out.toByteArray())
                hmac!!.update(old.signature)
            }
        }

        /* Digest the message */
        if (signing) {
            hmac!!.update(b)
        }
        var out = DnsOutput()
        name.toWireCanonical(out)
        out.writeU16(DnsClass.ANY) /* class */
        out.writeU32(0) /* ttl */
        alg.toWireCanonical(out)
        var time = timeSigned.time / 1000
        var timeHigh = (time shr 32).toInt()
        var timeLow = time and 0xFFFFFFFFL
        out.writeU16(timeHigh)
        out.writeU32(timeLow)
        out.writeU16(fudge)
        out.writeU16(error)
        out.writeU16(0) /* No other data */
        if (signing) {
            hmac!!.update(out.toByteArray())
        }
        val signature: ByteArray
        signature = if (signing) {
            hmac!!.doFinal()
        } else {
            ByteArray(0)
        }
        var other: ByteArray? = null
        if (error == DnsResponseCode.BADTIME) {
            out = DnsOutput()
            time = Date().time / 1000
            timeHigh = (time shr 32).toInt()
            timeLow = time and 0xFFFFFFFFL
            out.writeU16(timeHigh)
            out.writeU32(timeLow)
            other = out.toByteArray()
        }
        return TSIGRecord(
            name, DnsClass.ANY, 0, alg, timeSigned, fudge, signature, m.header.iD, error, other
        )
    }

    /**
     * Verifies a TSIG record on an incoming message.  Since this is only called
     * in the context where a TSIG is expected to be present, it is an error
     * if one is not present.  After calling this routine, DnsMessage.isVerified() may
     * be called on this message.
     *
     * @param m The message
     * @param b The message in unparsed form.  This is necessary since TSIG
     * signs the message in wire format, and we can't recreate the exact wire
     * format (with the same name compression).
     * @param old If this message is a response, the TSIG from the request
     *
     * @return The result of the verification (as an DnsResponseCode)
     *
     * @see DnsResponseCode
     */
    fun verify(m: DnsMessage, b: ByteArray, old: TSIGRecord?): Int {
        return verify(m, b, b.size, old).toInt()
    }

    /**
     * Verifies a TSIG record on an incoming message.  Since this is only called
     * in the context where a TSIG is expected to be present, it is an error
     * if one is not present.  After calling this routine, DnsMessage.isVerified() may
     * be called on this message.
     *
     * @param m The message
     * @param b An array containing the message in unparsed form.  This is
     * necessary since TSIG signs the message in wire format, and we can't
     * recreate the exact wire format (with the same name compression).
     * @param length The length of the message in the array.
     * @param old If this message is a response, the TSIG from the request
     *
     * @return The result of the verification (as an DnsResponseCode)
     *
     * @see DnsResponseCode
     */
    fun verify(m: DnsMessage, b: ByteArray?, length: Int, old: TSIGRecord?): Byte {
        m.tsigState = DnsMessage.TSIG_FAILED
        val tsig = m.tSIG
        hmac!!.reset()
        if (tsig == null) {
            return DnsResponseCode.FORMERR.toByte()
        }
        if (!tsig.name.equals(name) || !tsig.algorithm.equals(alg)) {
            if (check("verbose")) {
                System.err.println("BADKEY failure")
            }
            return DnsResponseCode.BADKEY.toByte()
        }
        val now = System.currentTimeMillis()
        val then = tsig.timeSigned.time
        val fudge = tsig.fudge.toLong()
        if (Math.abs(now - then) > fudge * 1000) {
            if (check("verbose")) {
                System.err.println("BADTIME failure")
            }
            return DnsResponseCode.BADTIME.toByte()
        }
        if (old != null && tsig.error != DnsResponseCode.BADKEY && tsig.error != DnsResponseCode.BADSIG) {
            val out = DnsOutput()
            out.writeU16(old.signature.size)
            hmac!!.update(out.toByteArray())
            hmac!!.update(old.signature)
        }
        m.header.decCount(DnsSection.ADDITIONAL)
        val header = m.header.toWire()
        m.header.incCount(DnsSection.ADDITIONAL)
        hmac!!.update(header)
        val len = m.tsigstart - header.size
        hmac!!.update(b, header.size, len)
        val out = DnsOutput()
        tsig.name.toWireCanonical(out)
        out.writeU16(tsig.dclass)
        out.writeU32(tsig.ttl)
        tsig.algorithm.toWireCanonical(out)
        val time = tsig.timeSigned.time / 1000
        val timeHigh = (time shr 32).toInt()
        val timeLow = time and 0xFFFFFFFFL
        out.writeU16(timeHigh)
        out.writeU32(timeLow)
        out.writeU16(tsig.fudge)
        out.writeU16(tsig.error)
        if (tsig.other != null) {
            out.writeU16(tsig.other!!.size)
            out.writeByteArray(tsig.other!!)
        } else {
            out.writeU16(0)
        }
        hmac!!.update(out.toByteArray())
        val signature = tsig.signature
        val digestLength = hmac!!.macLength
        val minDigestLength: Int
        minDigestLength = if (hmac!!.algorithm.lowercase(Locale.getDefault()).contains("md5")) {
            10
        } else {
            digestLength / 2
        }
        if (signature.size > digestLength) {
            if (check("verbose")) {
                System.err.println("BADSIG: signature too long")
            }
            return DnsResponseCode.BADSIG.toByte()
        } else if (signature.size < minDigestLength) {
            if (check("verbose")) {
                System.err.println("BADSIG: signature too short")
            }
            return DnsResponseCode.BADSIG.toByte()
        } else if (!verify(hmac, signature, true)) {
            if (check("verbose")) {
                System.err.println("BADSIG: signature verification")
            }
            return DnsResponseCode.BADSIG.toByte()
        }
        m.tsigState = DnsMessage.TSIG_VERIFIED
        return DnsResponseCode.NOERROR.toByte()
    }

    /**
     * Returns the maximum length of a TSIG record generated by this key.
     *
     * @see TSIGRecord
     */
    fun recordLength(): Int {
        return name.length() + 10 + alg.length() + 8 +  // time signed, fudge
                18 +  // 2 byte MAC length, 16 byte MAC
                4 +  // original id, error
                8 // 2 byte error length, 6 byte max error field.
    }

    class StreamVerifier(
        /**
         * A helper class for verifying multiple message responses.
         */
        private val key: TSIG, old: TSIGRecord?
    ) {
        private val verifier: Mac?
        private var nresponses: Int
        private var lastsigned = 0
        private var lastTSIG: TSIGRecord?

        /**
         * Creates an object to verify a multiple message response
         */
        init {
            verifier = key.hmac
            nresponses = 0
            lastTSIG = old
        }

        /**
         * Verifies a TSIG record on an incoming message that is part of a
         * multiple message response.
         * TSIG records must be present on the first and last messages, and
         * at least every 100 records in between.
         * After calling this routine, DnsMessage.isVerified() may be called on
         * this message.
         *
         * @param m The message
         * @param b The message in unparsed form
         *
         * @return The result of the verification (as an DnsResponseCode)
         *
         * @see DnsResponseCode
         */
        fun verify(m: DnsMessage, b: ByteArray): Int {
            val tsig = m.tSIG
            nresponses++
            if (nresponses == 1) {
                val result = key.verify(m, b, lastTSIG)
                if (result == DnsResponseCode.NOERROR) {
                    val signature = tsig!!.signature
                    val out = DnsOutput()
                    out.writeU16(signature.size)
                    verifier!!.update(out.toByteArray())
                    verifier.update(signature)
                }
                lastTSIG = tsig
                return result
            }
            if (tsig != null) {
                m.header.decCount(DnsSection.ADDITIONAL)
            }
            val header = m.header.toWire()
            if (tsig != null) {
                m.header.incCount(DnsSection.ADDITIONAL)
            }
            verifier!!.update(header)
            val len: Int
            len = if (tsig == null) {
                b.size - header.size
            } else {
                m.tsigstart - header.size
            }
            verifier.update(b, header.size, len)
            if (tsig != null) {
                lastsigned = nresponses
                lastTSIG = tsig
            } else {
                val required = nresponses - lastsigned >= 100
                return if (required) {
                    m.tsigState = DnsMessage.TSIG_FAILED
                    DnsResponseCode.FORMERR
                } else {
                    m.tsigState = DnsMessage.TSIG_INTERMEDIATE
                    DnsResponseCode.NOERROR
                }
            }
            if (!tsig.name.equals(key.name) || !tsig.algorithm.equals(key.alg)) {
                if (check("verbose")) {
                    System.err.println("BADKEY failure")
                }
                m.tsigState = DnsMessage.TSIG_FAILED
                return DnsResponseCode.BADKEY
            }
            var out = DnsOutput()
            val time = tsig.timeSigned.time / 1000
            val timeHigh = (time shr 32).toInt()
            val timeLow = time and 0xFFFFFFFFL
            out.writeU16(timeHigh)
            out.writeU32(timeLow)
            out.writeU16(tsig.fudge)
            verifier.update(out.toByteArray())
            if (verify(verifier, tsig.signature) == false) {
                if (check("verbose")) {
                    System.err.println("BADSIG failure")
                }
                m.tsigState = DnsMessage.TSIG_FAILED
                return DnsResponseCode.BADSIG
            }
            verifier.reset()
            out = DnsOutput()
            out.writeU16(tsig.signature.size)
            verifier.update(out.toByteArray())
            verifier.update(tsig.signature)
            m.tsigState = DnsMessage.TSIG_VERIFIED
            return DnsResponseCode.NOERROR
        }
    }

    companion object {
        val regex = "[:/]".toRegex()

        /**
         * The domain name representing the HMAC-MD5 algorithm.
         */
        val HMAC_MD5 = Name.fromConstantString("HMAC-MD5.SIG-ALG.REG.INT.")

        /**
         * The domain name representing the HMAC-MD5 algorithm (deprecated).
         */
        val HMAC = HMAC_MD5

        /**
         * The domain name representing the HMAC-SHA1 algorithm.
         */
        val HMAC_SHA1 = Name.fromConstantString("hmac-sha1.")

        /**
         * The domain name representing the HMAC-SHA224 algorithm.
         * Note that SHA224 is not supported by Java out-of-the-box, this requires use
         * of a third party provider like BouncyCastle.org.
         */
        val HMAC_SHA224 = Name.fromConstantString("hmac-sha224.")

        /**
         * The domain name representing the HMAC-SHA256 algorithm.
         */
        val HMAC_SHA256 = Name.fromConstantString("hmac-sha256.")

        /**
         * The domain name representing the HMAC-SHA384 algorithm.
         */
        val HMAC_SHA384 = Name.fromConstantString("hmac-sha384.")

        /**
         * The domain name representing the HMAC-SHA512 algorithm.
         */
        val HMAC_SHA512 = Name.fromConstantString("hmac-sha512.")
        private val algMap = ObjectMap<Name, String>()

        /**
         * The default fudge value for outgoing packets.  Can be overridden by the
         * tsigfudge option.
         */
        const val FUDGE: Short = 300

        init {
            algMap.put(HMAC_MD5, "HmacMD5")
            algMap.put(HMAC_SHA1, "HmacSHA1")
            algMap.put(HMAC_SHA224, "HmacSHA224")
            algMap.put(HMAC_SHA256, "HmacSHA256")
            algMap.put(HMAC_SHA384, "HmacSHA384")
            algMap.put(HMAC_SHA512, "HmacSHA512")
        }
        /**
         * Verifies the data (computes the secure hash and compares it to the input)
         *
         * @param mac The HMAC generator
         * @param signature The signature to compare against
         * @param truncation_ok If true, the signature may be truncated; only the
         * number of bytes in the provided signature are compared.
         *
         * @return true if the signature matches, false otherwise
         */
        /**
         * Verifies the data (computes the secure hash and compares it to the input)
         *
         * @param mac The HMAC generator
         * @param signature The signature to compare against
         *
         * @return true if the signature matches, false otherwise
         */
        private fun verify(mac: Mac?, signature: ByteArray, truncation_ok: Boolean = false): Boolean {
            var expected = mac!!.doFinal()
            if (truncation_ok && signature.size < expected.size) {
                val truncated = ByteArray(signature.size)
                System.arraycopy(expected, 0, truncated, 0, truncated.size)
                expected = truncated
            }
            return Arrays.equals(signature, expected)
        }

        fun nameToAlgorithm(name: Name): String {
            val alg = algMap[name]
            if (alg != null) {
                return alg
            }
            throw IllegalArgumentException("Unknown algorithm")
        }

        fun algorithmToName(alg: String?): Name {

            // false identity check because it's string comparisons.
            val foundKey = algMap.findKey(alg, false)
            if (foundKey != null) {
                return foundKey
            }
            throw IllegalArgumentException("Unknown algorithm")
        }

        /**
         * Creates a new TSIG object, which can be used to sign or verify a message.
         *
         * @param str The TSIG key, in the form name:secret, name/secret,
         * alg:name:secret, or alg/name/secret.  If an algorithm is specified, it must
         * be "hmac-md5", "hmac-sha1", or "hmac-sha256".
         *
         * @throws IllegalArgumentException The string does not contain both a name
         * and secret.
         * @throws IllegalArgumentException The key name is an invalid name
         * @throws IllegalArgumentException The key data is improperly encoded
         */
        fun fromString(str: String): TSIG {

            var parts: Array<String> = str.split(regex, limit = 3).toTypedArray()
            require(parts.size >= 2) { "Invalid TSIG key " + "specification" }

            if (parts.size == 3) {
                parts = try {
                    return TSIG(parts[0], parts[1], parts[2])
                } catch (e: IllegalArgumentException) {
                    str.split(regex, limit = 2).toTypedArray()
                }
            }
            return TSIG(HMAC_MD5, parts[0], parts[1])
        }
    }
}
