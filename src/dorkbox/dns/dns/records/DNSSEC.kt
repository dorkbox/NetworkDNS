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

import dorkbox.dns.dns.DnsInput
import dorkbox.dns.dns.DnsOutput
import dorkbox.dns.dns.Mnemonic
import dorkbox.dns.dns.Name
import dorkbox.dns.dns.constants.DnsClass
import dorkbox.dns.dns.constants.DnsSection
import java.io.IOException
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.DSAPrivateKey
import java.security.interfaces.DSAPublicKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.DSAPublicKeySpec
import java.security.spec.ECFieldFp
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.EllipticCurve
import java.security.spec.RSAPublicKeySpec
import java.util.*

/**
 * Constants and methods relating to DNSSEC.
 *
 *
 * DNSSEC provides authentication for DNS information.
 *
 * @author Brian Wellington
 * @see RRSIGRecord
 *
 * @see DNSKEYRecord
 *
 * @see RRset
 */
object DNSSEC {
    // RFC 4357 DnsSection 11.4
    private val GOST = ECKeyInfo(
        32,
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94",
        "A6",
        "1",
        "8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893"
    )

    // RFC 5114 DnsSection 2.6
    private val ECDSA_P256 = ECKeyInfo(
        32,
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
    )

    // RFC 5114 DnsSection 2.7
    private val ECDSA_P384 = ECKeyInfo(
        48,
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
        "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
        "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"
    )
    private const val ASN1_SEQ = 0x30
    private const val ASN1_INT = 0x2
    private const val DSA_LEN = 20

    /**
     * Creates a byte array containing the concatenation of the fields of the
     * SIG(0) record and the message to be signed.  This does not perform
     * a cryptographic digest.
     *
     * @param sig The SIG record used to sign the rrset.
     * @param msg The message to be signed.
     * @param previous If this is a response, the signature from the query.
     *
     * @return The data to be cryptographically signed.
     */
    fun digestMessage(sig: SIGRecord, msg: DnsMessage, previous: ByteArray?): ByteArray {
        val out = DnsOutput()
        digestSIG(out, sig)
        if (previous != null) {
            out.writeByteArray(previous)
        }
        msg.toWire(out)
        return out.toByteArray()
    }

    private fun digestSIG(out: DnsOutput, sig: SIGBase) {
        out.writeU16(sig.typeCovered)
        out.writeU8(sig.algorithm)
        out.writeU8(sig.labels)
        out.writeU32(sig.origTTL)
        out.writeU32(
            sig.expire.time / 1000
        )
        out.writeU32(
            sig.timeSigned.time / 1000
        )
        out.writeU16(sig.footprint)
        sig.signer.toWireCanonical(out)
    }

    private fun trimByteArray(array: ByteArray): ByteArray {
        return if (array[0].toInt() == 0) {
            val trimmedArray = ByteArray(array.size - 1)
            System.arraycopy(array, 1, trimmedArray, 0, array.size - 1)
            trimmedArray
        } else {
            array
        }
    }

    private fun writeBigInteger(out: DnsOutput, `val`: BigInteger) {
        val b = trimByteArray(`val`.toByteArray())
        out.writeByteArray(b)
    }

    private fun writePaddedBigInteger(out: DnsOutput, `val`: BigInteger, len: Int) {
        val b = trimByteArray(`val`.toByteArray())
        require(b.size <= len)
        if (b.size < len) {
            val pad = ByteArray(len - b.size)
            out.writeByteArray(pad)
        }
        out.writeByteArray(b)
    }

    private fun writePaddedBigIntegerLittleEndian(out: DnsOutput, `val`: BigInteger, len: Int) {
        val b = trimByteArray(`val`.toByteArray())
        require(b.size <= len)
        reverseByteArray(b)
        out.writeByteArray(b)
        if (b.size < len) {
            val pad = ByteArray(len - b.size)
            out.writeByteArray(pad)
        }
    }

    /**
     * Converts a KEY/DNSKEY record into a PublicKey
     */
    @JvmStatic
    @Throws(DNSSECException::class)
    fun toPublicKey(r: KEYBase): PublicKey {
        val alg = r.algorithm
        return try {
            when (alg) {
                Algorithm.RSAMD5, Algorithm.RSASHA1, Algorithm.RSA_NSEC3_SHA1, Algorithm.RSASHA256, Algorithm.RSASHA512 -> toRSAPublicKey(r)
                Algorithm.DSA, Algorithm.DSA_NSEC3_SHA1 -> toDSAPublicKey(r)
                Algorithm.ECC_GOST -> toECGOSTPublicKey(r, GOST)
                Algorithm.ECDSAP256SHA256 -> toECDSAPublicKey(r, ECDSA_P256)
                Algorithm.ECDSAP384SHA384 -> toECDSAPublicKey(r, ECDSA_P384)
                else -> throw UnsupportedAlgorithmException(alg)
            }
        } catch (e: IOException) {
            throw MalformedKeyException(r)
        } catch (e: GeneralSecurityException) {
            throw DNSSECException(e.toString())
        }
    }

    @Throws(IOException::class, GeneralSecurityException::class)
    private fun toRSAPublicKey(r: KEYBase): PublicKey {
        val `in` = DnsInput(r.key!!)
        var exponentLength = `in`.readU8()
        if (exponentLength == 0) {
            exponentLength = `in`.readU16()
        }
        val exponent = readBigInteger(`in`, exponentLength)
        val modulus = readBigInteger(`in`)
        val factory = KeyFactory.getInstance("RSA")
        return factory.generatePublic(RSAPublicKeySpec(modulus, exponent))
    }

    @Throws(IOException::class)
    private fun readBigInteger(`in`: DnsInput, len: Int): BigInteger {
        val b = `in`.readByteArray(len)
        return BigInteger(1, b)
    }

    private fun readBigInteger(`in`: DnsInput): BigInteger {
        val b = `in`.readByteArray()
        return BigInteger(1, b)
    }

    @Throws(IOException::class, GeneralSecurityException::class, MalformedKeyException::class)
    private fun toDSAPublicKey(r: KEYBase): PublicKey {
        val `in` = DnsInput(r.key!!)
        val t = `in`.readU8()
        if (t > 8) {
            throw MalformedKeyException(r)
        }
        val q = readBigInteger(`in`, 20)
        val p = readBigInteger(`in`, 64 + t * 8)
        val g = readBigInteger(`in`, 64 + t * 8)
        val y = readBigInteger(`in`, 64 + t * 8)
        val factory = KeyFactory.getInstance("DSA")
        return factory.generatePublic(DSAPublicKeySpec(y, p, q, g))
    }

    @Throws(IOException::class, GeneralSecurityException::class, MalformedKeyException::class)
    private fun toECGOSTPublicKey(r: KEYBase, keyinfo: ECKeyInfo): PublicKey {
        val `in` = DnsInput(r.key!!)
        val x = readBigIntegerLittleEndian(`in`, keyinfo.length)
        val y = readBigIntegerLittleEndian(`in`, keyinfo.length)
        val q = ECPoint(x, y)
        val factory = KeyFactory.getInstance("ECGOST3410")
        return factory.generatePublic(ECPublicKeySpec(q, keyinfo.spec))
    }

    @Throws(IOException::class)
    private fun readBigIntegerLittleEndian(`in`: DnsInput, len: Int): BigInteger {
        val b = `in`.readByteArray(len)
        reverseByteArray(b)
        return BigInteger(1, b)
    }

    private fun reverseByteArray(array: ByteArray) {
        for (i in 0 until array.size / 2) {
            val j = array.size - i - 1
            val tmp = array[i]
            array[i] = array[j]
            array[j] = tmp
        }
    }

    @Throws(IOException::class, GeneralSecurityException::class, MalformedKeyException::class)
    private fun toECDSAPublicKey(r: KEYBase, keyinfo: ECKeyInfo): PublicKey {
        val `in` = DnsInput(r.key!!)

        // RFC 6605 DnsSection 4
        val x = readBigInteger(`in`, keyinfo.length)
        val y = readBigInteger(`in`, keyinfo.length)
        val q = ECPoint(x, y)
        val factory = KeyFactory.getInstance("EC")
        return factory.generatePublic(ECPublicKeySpec(q, keyinfo.spec))
    }

    private fun fromRSAPublicKey(key: RSAPublicKey): ByteArray {
        val out = DnsOutput()
        val exponent = key.publicExponent
        val modulus = key.modulus
        val exponentLength = BigIntegerLength(exponent)
        if (exponentLength < 256) {
            out.writeU8(exponentLength)
        } else {
            out.writeU8(0)
            out.writeU16(exponentLength)
        }
        writeBigInteger(out, exponent)
        writeBigInteger(out, modulus)
        return out.toByteArray()
    }

    private fun fromDSAPublicKey(key: DSAPublicKey): ByteArray {
        val out = DnsOutput()
        val q = key.params.q
        val p = key.params.p
        val g = key.params.g
        val y = key.y
        val t = (p.toByteArray().size - 64) / 8
        out.writeU8(t)
        writeBigInteger(out, q)
        writeBigInteger(out, p)
        writePaddedBigInteger(out, g, 8 * t + 64)
        writePaddedBigInteger(out, y, 8 * t + 64)
        return out.toByteArray()
    }

    private fun fromECGOSTPublicKey(key: ECPublicKey, keyinfo: ECKeyInfo): ByteArray {
        val out = DnsOutput()
        val x = key.w.affineX
        val y = key.w.affineY
        writePaddedBigIntegerLittleEndian(out, x, keyinfo.length)
        writePaddedBigIntegerLittleEndian(out, y, keyinfo.length)
        return out.toByteArray()
    }

    private fun fromECDSAPublicKey(key: ECPublicKey, keyinfo: ECKeyInfo): ByteArray {
        val out = DnsOutput()
        val x = key.w.affineX
        val y = key.w.affineY
        writePaddedBigInteger(out, x, keyinfo.length)
        writePaddedBigInteger(out, y, keyinfo.length)
        return out.toByteArray()
    }

    /**
     * Builds a DNSKEY record from a PublicKey
     */
    @Throws(DNSSECException::class)
    fun fromPublicKey(key: PublicKey?, alg: Int): ByteArray {
        return when (alg) {
            Algorithm.RSAMD5, Algorithm.RSASHA1, Algorithm.RSA_NSEC3_SHA1, Algorithm.RSASHA256, Algorithm.RSASHA512 -> {
                if (key !is RSAPublicKey) {
                    throw IncompatibleKeyException()
                }
                fromRSAPublicKey(key)
            }
            Algorithm.DSA, Algorithm.DSA_NSEC3_SHA1 -> {
                if (key !is DSAPublicKey) {
                    throw IncompatibleKeyException()
                }
                fromDSAPublicKey(key)
            }
            Algorithm.ECC_GOST -> {
                if (key !is ECPublicKey) {
                    throw IncompatibleKeyException()
                }
                fromECGOSTPublicKey(key, GOST)
            }
            Algorithm.ECDSAP256SHA256 -> {
                if (key !is ECPublicKey) {
                    throw IncompatibleKeyException()
                }
                fromECDSAPublicKey(key, ECDSA_P256)
            }
            Algorithm.ECDSAP384SHA384 -> {
                if (key !is ECPublicKey) {
                    throw IncompatibleKeyException()
                }
                fromECDSAPublicKey(key, ECDSA_P384)
            }
            else -> throw UnsupportedAlgorithmException(alg)
        }
    }

    /**
     * Verify a DNSSEC signature.
     *
     * @param rrset The data to be verified.
     * @param rrsig The RRSIG record containing the signature.
     * @param key The DNSKEY record to verify the signature with.
     *
     * @throws UnsupportedAlgorithmException The algorithm is unknown
     * @throws MalformedKeyException The key is malformed
     * @throws KeyMismatchException The key and signature do not match
     * @throws SignatureExpiredException The signature has expired
     * @throws SignatureNotYetValidException The signature is not yet valid
     * @throws SignatureVerificationException The signature does not verify.
     * @throws DNSSECException Some other error occurred.
     */
    @Throws(DNSSECException::class)
    fun verify(rrset: RRset, rrsig: RRSIGRecord, key: DNSKEYRecord) {
        if (!matches(rrsig, key)) {
            throw KeyMismatchException(key, rrsig)
        }
        val now = Date()
        if (now.compareTo(rrsig.expire) > 0) {
            throw SignatureExpiredException(rrsig.expire, now)
        }
        if (now.compareTo(rrsig.timeSigned) < 0) {
            throw SignatureNotYetValidException(rrsig.timeSigned, now)
        }
        verify(key.publicKey, rrsig.algorithm, digestRRset(rrsig, rrset), rrsig.signature)
    }

    /**
     * Creates a byte array containing the concatenation of the fields of the
     * SIG record and the RRsets to be signed/verified.  This does not perform
     * a cryptographic digest.
     *
     * @param rrsig The RRSIG record used to sign/verify the rrset.
     * @param rrset The data to be signed/verified.
     *
     * @return The data to be cryptographically signed or verified.
     */
    fun digestRRset(rrsig: RRSIGRecord, rrset: RRset): ByteArray {
        val out = DnsOutput()
        digestSIG(out, rrsig)
        var size = rrset.size()
        val records = arrayOfNulls<DnsRecord>(size)
        val it = rrset.rrs()
        val name = rrset.name
        var wild: Name? = null
        val sigLabels = rrsig.labels + 1 // Add the root label back.
        if (name.labels() > sigLabels) {
            wild = name.wild(name.labels() - sigLabels)
        }
        while (it.hasNext()) {
            records[--size] = it.next() as DnsRecord?
        }
        Arrays.sort(records)
        val header = DnsOutput()
        if (wild != null) {
            wild.toWireCanonical(header)
        } else {
            name.toWireCanonical(header)
        }
        header.writeU16(rrset.type)
        header.writeU16(rrset.dClass)
        header.writeU32(rrsig.origTTL)
        for (i in records.indices) {
            out.writeByteArray(header.toByteArray())
            val lengthPosition = out.current()
            out.writeU16(0)
            out.writeByteArray(records[i]!!.rdataToWireCanonical())
            val rrlength = out.current() - lengthPosition - 2
            out.save()
            out.jump(lengthPosition)
            out.writeU16(rrlength)
            out.restore()
        }
        return out.toByteArray()
    }

    @Throws(DNSSECException::class)
    private fun verify(key: PublicKey, alg: Int, data: ByteArray, signature: ByteArray) {
        var signature = signature
        if (key is DSAPublicKey) {
            signature = try {
                DSASignaturefromDNS(signature)
            } catch (e: IOException) {
                throw IllegalStateException()
            }
        } else if (key is ECPublicKey) {
            signature = try {
                when (alg) {
                    Algorithm.ECC_GOST -> ECGOSTSignaturefromDNS(signature, GOST)
                    Algorithm.ECDSAP256SHA256 -> ECDSASignaturefromDNS(signature, ECDSA_P256)
                    Algorithm.ECDSAP384SHA384 -> ECDSASignaturefromDNS(signature, ECDSA_P384)
                    else -> throw UnsupportedAlgorithmException(alg)
                }
            } catch (e: IOException) {
                throw IllegalStateException()
            }
        }
        try {
            val s = Signature.getInstance(algString(alg))
            s.initVerify(key)
            s.update(data)
            if (!s.verify(signature)) {
                throw SignatureVerificationException()
            }
        } catch (e: GeneralSecurityException) {
            throw DNSSECException(e.toString())
        }
    }

    /**
     * Convert an algorithm number to the corresponding JCA string.
     *
     * @param alg The algorithm number.
     *
     * @throws UnsupportedAlgorithmException The algorithm is unknown.
     */
    @Throws(UnsupportedAlgorithmException::class)
    fun algString(alg: Int): String {
        return when (alg) {
            Algorithm.RSAMD5 -> "MD5withRSA"
            Algorithm.DSA, Algorithm.DSA_NSEC3_SHA1 -> "SHA1withDSA"
            Algorithm.RSASHA1, Algorithm.RSA_NSEC3_SHA1 -> "SHA1withRSA"
            Algorithm.RSASHA256 -> "SHA256withRSA"
            Algorithm.RSASHA512 -> "SHA512withRSA"
            Algorithm.ECC_GOST -> "GOST3411withECGOST3410"
            Algorithm.ECDSAP256SHA256 -> "SHA256withECDSA"
            Algorithm.ECDSAP384SHA384 -> "SHA384withECDSA"
            else -> throw UnsupportedAlgorithmException(alg)
        }
    }

    @Throws(DNSSECException::class, IOException::class)
    private fun DSASignaturefromDNS(dns: ByteArray): ByteArray {
        if (dns.size != 1 + DSA_LEN * 2) {
            throw SignatureVerificationException()
        }
        val `in` = DnsInput(dns)
        val out = DnsOutput()
        val t = `in`.readU8()
        val r = `in`.readByteArray(DSA_LEN)
        var rlen = DSA_LEN
        if (r[0] < 0) {
            rlen++
        }
        val s = `in`.readByteArray(DSA_LEN)
        var slen = DSA_LEN
        if (s[0] < 0) {
            slen++
        }
        out.writeU8(ASN1_SEQ)
        out.writeU8(rlen + slen + 4)
        out.writeU8(ASN1_INT)
        out.writeU8(rlen)
        if (rlen > DSA_LEN) {
            out.writeU8(0)
        }
        out.writeByteArray(r)
        out.writeU8(ASN1_INT)
        out.writeU8(slen)
        if (slen > DSA_LEN) {
            out.writeU8(0)
        }
        out.writeByteArray(s)
        return out.toByteArray()
    }

    @Throws(DNSSECException::class, IOException::class)
    private fun ECGOSTSignaturefromDNS(signature: ByteArray, keyinfo: ECKeyInfo): ByteArray {
        if (signature.size != keyinfo.length * 2) {
            throw SignatureVerificationException()
        }
        // Wire format is equal to the engine input
        return signature
    }

    @Throws(DNSSECException::class, IOException::class)
    private fun ECDSASignaturefromDNS(signature: ByteArray, keyinfo: ECKeyInfo): ByteArray {
        if (signature.size != keyinfo.length * 2) {
            throw SignatureVerificationException()
        }
        val `in` = DnsInput(signature)
        val out = DnsOutput()
        val r = `in`.readByteArray(keyinfo.length)
        var rlen = keyinfo.length
        if (r[0] < 0) {
            rlen++
        }
        val s = `in`.readByteArray(keyinfo.length)
        var slen = keyinfo.length
        if (s[0] < 0) {
            slen++
        }
        out.writeU8(ASN1_SEQ)
        out.writeU8(rlen + slen + 4)
        out.writeU8(ASN1_INT)
        out.writeU8(rlen)
        if (rlen > keyinfo.length) {
            out.writeU8(0)
        }
        out.writeByteArray(r)
        out.writeU8(ASN1_INT)
        out.writeU8(slen)
        if (slen > keyinfo.length) {
            out.writeU8(0)
        }
        out.writeByteArray(s)
        return out.toByteArray()
    }

    private fun matches(sig: SIGBase, key: KEYBase): Boolean {
        return key.algorithm == sig.algorithm && key.footprint == sig.footprint && (key.name == sig.signer)
    }
    /**
     * Generate a DNSSEC signature.  key and privateKey must refer to the
     * same underlying cryptographic key.
     *
     * @param rrset The data to be signed
     * @param key The DNSKEY record to use as part of signing
     * @param privkey The PrivateKey to use when signing
     * @param inception The time at which the signatures should become valid
     * @param expiration The time at which the signatures should expire
     * @param provider The name of the JCA provider.  If non-null, it will be
     * passed to JCA getInstance() methods.
     *
     * @return The generated signature
     *
     * @throws UnsupportedAlgorithmException The algorithm is unknown
     * @throws MalformedKeyException The key is malformed
     * @throws DNSSECException Some other error occurred.
     */
    /**
     * Generate a DNSSEC signature.  key and privateKey must refer to the
     * same underlying cryptographic key.
     *
     * @param rrset The data to be signed
     * @param key The DNSKEY record to use as part of signing
     * @param privkey The PrivateKey to use when signing
     * @param inception The time at which the signatures should become valid
     * @param expiration The time at which the signatures should expire
     *
     * @return The generated signature
     *
     * @throws UnsupportedAlgorithmException The algorithm is unknown
     * @throws MalformedKeyException The key is malformed
     * @throws DNSSECException Some other error occurred.
     */
    @Throws(DNSSECException::class)
    fun sign(
        rrset: RRset,
        key: DNSKEYRecord,
        privkey: PrivateKey?,
        inception: Date,
        expiration: Date,
        provider: String? = null
    ): RRSIGRecord {
        val alg = key.algorithm
        checkAlgorithm(privkey, alg)
        val rrsig = RRSIGRecord(
            rrset.name, rrset.dClass, rrset.TTL, rrset.type, alg, rrset.TTL, expiration, inception, key.footprint, key.name, byteArrayOf()
        )
        rrsig.signature = sign(privkey, key.publicKey, alg, digestRRset(rrsig, rrset), provider)
        return rrsig
    }

    @Throws(DNSSECException::class)
    private fun sign(privkey: PrivateKey?, pubkey: PublicKey, alg: Int, data: ByteArray, provider: String?): ByteArray {
        var signature: ByteArray
        try {
            val s: Signature
            s = if (provider != null) {
                Signature.getInstance(algString(alg), provider)
            } else {
                Signature.getInstance(algString(alg))
            }
            s.initSign(privkey)
            s.update(data)
            signature = s.sign()
        } catch (e: GeneralSecurityException) {
            throw DNSSECException(e.toString())
        }
        if (pubkey is DSAPublicKey) {
            signature = try {
                val P = pubkey.params.p
                val t = (BigIntegerLength(P) - 64) / 8
                DSASignaturetoDNS(signature, t)
            } catch (e: IOException) {
                throw IllegalStateException()
            }
        } else if (pubkey is ECPublicKey) {
            try {
                when (alg) {
                    Algorithm.ECC_GOST -> {}
                    Algorithm.ECDSAP256SHA256 -> signature = ECDSASignaturetoDNS(signature, ECDSA_P256)
                    Algorithm.ECDSAP384SHA384 -> signature = ECDSASignaturetoDNS(signature, ECDSA_P384)
                    else -> throw UnsupportedAlgorithmException(alg)
                }
            } catch (e: IOException) {
                throw IllegalStateException()
            }
        }
        return signature
    }

    private fun BigIntegerLength(i: BigInteger): Int {
        return (i.bitLength() + 7) / 8
    }

    @Throws(IOException::class)
    private fun DSASignaturetoDNS(signature: ByteArray, t: Int): ByteArray {
        val `in` = DnsInput(signature)
        val out = DnsOutput()
        out.writeU8(t)
        var tmp = `in`.readU8()
        if (tmp != ASN1_SEQ) {
            throw IOException()
        }
        val seqlen = `in`.readU8()
        tmp = `in`.readU8()
        if (tmp != ASN1_INT) {
            throw IOException()
        }
        val rlen = `in`.readU8()
        if (rlen == DSA_LEN + 1) {
            if (`in`.readU8() != 0) {
                throw IOException()
            }
        } else if (rlen != DSA_LEN) {
            throw IOException()
        }
        var bytes = `in`.readByteArray(DSA_LEN)
        out.writeByteArray(bytes!!)
        tmp = `in`.readU8()
        if (tmp != ASN1_INT) {
            throw IOException()
        }
        val slen = `in`.readU8()
        if (slen == DSA_LEN + 1) {
            if (`in`.readU8() != 0) {
                throw IOException()
            }
        } else if (slen != DSA_LEN) {
            throw IOException()
        }
        bytes = `in`.readByteArray(DSA_LEN)
        out.writeByteArray(bytes)
        return out.toByteArray()
    }

    @Throws(IOException::class)
    private fun ECDSASignaturetoDNS(signature: ByteArray, keyinfo: ECKeyInfo): ByteArray {
        val `in` = DnsInput(signature)
        val out = DnsOutput()
        var tmp = `in`.readU8()
        if (tmp != ASN1_SEQ) {
            throw IOException()
        }
        val seqlen = `in`.readU8()
        tmp = `in`.readU8()
        if (tmp != ASN1_INT) {
            throw IOException()
        }
        val rlen = `in`.readU8()
        if (rlen == keyinfo.length + 1) {
            if (`in`.readU8() != 0) {
                throw IOException()
            }
        } else if (rlen != keyinfo.length) {
            throw IOException()
        }
        var bytes = `in`.readByteArray(keyinfo.length)
        out.writeByteArray(bytes!!)
        tmp = `in`.readU8()
        if (tmp != ASN1_INT) {
            throw IOException()
        }
        val slen = `in`.readU8()
        if (slen == keyinfo.length + 1) {
            if (`in`.readU8() != 0) {
                throw IOException()
            }
        } else if (slen != keyinfo.length) {
            throw IOException()
        }
        bytes = `in`.readByteArray(keyinfo.length)
        out.writeByteArray(bytes)
        return out.toByteArray()
    }

    @Throws(UnsupportedAlgorithmException::class)
    fun checkAlgorithm(key: PrivateKey?, alg: Int) {
        when (alg) {
            Algorithm.RSAMD5, Algorithm.RSASHA1, Algorithm.RSA_NSEC3_SHA1, Algorithm.RSASHA256, Algorithm.RSASHA512 -> if (key !is RSAPrivateKey) {
                throw IncompatibleKeyException()
            }
            Algorithm.DSA, Algorithm.DSA_NSEC3_SHA1 -> if (key !is DSAPrivateKey) {
                throw IncompatibleKeyException()
            }
            Algorithm.ECC_GOST, Algorithm.ECDSAP256SHA256, Algorithm.ECDSAP384SHA384 -> if (key !is ECPrivateKey) {
                throw IncompatibleKeyException()
            }
            else -> throw UnsupportedAlgorithmException(alg)
        }
    }

    @Throws(DNSSECException::class)
    fun signMessage(
        dnsMessage: DnsMessage,
        previous: SIGRecord?,
        key: KEYRecord,
        privkey: PrivateKey,
        inception: Date,
        expiration: Date
    ): SIGRecord {
        val alg = key.algorithm
        checkAlgorithm(privkey, alg)
        val sig = SIGRecord(Name.root, DnsClass.ANY, 0, 0, alg, 0, expiration, inception, key.footprint, key.name, byteArrayOf())
        val out = DnsOutput()
        digestSIG(out, sig)
        if (previous != null) {
            out.writeByteArray(previous.signature)
        }
        out.writeByteArray(dnsMessage.toWire())
        sig.signature = sign(privkey, key.publicKey, alg, out.toByteArray(), null)
        return sig
    }

    @Throws(DNSSECException::class)
    fun verifyMessage(dnsMessage: DnsMessage, bytes: ByteArray?, sig: SIGRecord, previous: SIGRecord?, key: KEYRecord) {
        if (dnsMessage.sig0start == 0) {
            throw NoSignatureException()
        }
        if (!matches(sig, key)) {
            throw KeyMismatchException(key, sig)
        }
        val now = Date()
        if (now.compareTo(sig.expire) > 0) {
            throw SignatureExpiredException(sig.expire, now)
        }
        if (now.compareTo(sig.timeSigned) < 0) {
            throw SignatureNotYetValidException(sig.timeSigned, now)
        }
        val out = DnsOutput()
        digestSIG(out, sig)
        if (previous != null) {
            out.writeByteArray(previous.signature)
        }
        val header = dnsMessage.header.clone() as Header
        header.decCount(DnsSection.ADDITIONAL)
        out.writeByteArray(header.toWire())
        out.writeByteArray(bytes!!, Header.LENGTH, dnsMessage.sig0start - Header.LENGTH)
        verify(key.publicKey, sig.algorithm, out.toByteArray(), sig.signature)
    }

    /**
     * Generate the digest value for a DS key
     *
     * @param key Which is covered by the DS record
     * @param digestid The type of digest
     *
     * @return The digest value as an array of bytes
     */
    fun generateDSDigest(key: DNSKEYRecord, digestid: Int): ByteArray {
        val digest: MessageDigest
        digest = try {
            when (digestid) {
                DSRecord.Digest.SHA1 -> MessageDigest.getInstance("sha-1")
                DSRecord.Digest.SHA256 -> MessageDigest.getInstance("sha-256")
                DSRecord.Digest.GOST3411 -> MessageDigest.getInstance("GOST3411")
                DSRecord.Digest.SHA384 -> MessageDigest.getInstance("sha-384")
                else -> throw IllegalArgumentException("unknown DS digest type $digestid")
            }
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalStateException("no message digest support")
        }
        digest.update(
            key.name.toWireCanonical()
        )
        digest.update(key.rdataToWireCanonical())
        return digest.digest()
    }

    object Algorithm {
        /**
         * RSA/MD5 public key (deprecated)
         */
        const val RSAMD5 = 1

        /**
         * Diffie Hellman key
         */
        const val DH = 2

        /**
         * DSA public key
         */
        const val DSA = 3

        /**
         * RSA/SHA1 public key
         */
        const val RSASHA1 = 5

        /**
         * DSA/SHA1, NSEC3-aware public key
         */
        const val DSA_NSEC3_SHA1 = 6

        /**
         * RSA/SHA1, NSEC3-aware public key
         */
        const val RSA_NSEC3_SHA1 = 7

        /**
         * RSA/SHA256 public key
         */
        const val RSASHA256 = 8

        /**
         * RSA/SHA512 public key
         */
        const val RSASHA512 = 10

        /**
         * GOST R 34.10-2001.
         * This requires an external cryptography provider,
         * such as BouncyCastle.
         */
        const val ECC_GOST = 12

        /**
         * ECDSA Curve P-256 with SHA-256 public key
         */
        const val ECDSAP256SHA256 = 13

        /**
         * ECDSA Curve P-384 with SHA-384 public key
         */
        const val ECDSAP384SHA384 = 14

        /**
         * Indirect keys; the actual key is elsewhere.
         */
        const val INDIRECT = 252

        /**
         * Private algorithm, specified by domain name
         */
        const val PRIVATEDNS = 253

        /**
         * Private algorithm, specified by OID
         */
        const val PRIVATEOID = 254
        private val algs = Mnemonic("DNSSEC algorithm", Mnemonic.CASE_UPPER)

        init {
            algs.setMaximum(0xFF)
            algs.setNumericAllowed(true)
            algs.add(RSAMD5, "RSAMD5")
            algs.add(DH, "DH")
            algs.add(DSA, "DSA")
            algs.add(RSASHA1, "RSASHA1")
            algs.add(DSA_NSEC3_SHA1, "DSA-NSEC3-SHA1")
            algs.add(RSA_NSEC3_SHA1, "RSA-NSEC3-SHA1")
            algs.add(RSASHA256, "RSASHA256")
            algs.add(RSASHA512, "RSASHA512")
            algs.add(ECC_GOST, "ECC-GOST")
            algs.add(ECDSAP256SHA256, "ECDSAP256SHA256")
            algs.add(ECDSAP384SHA384, "ECDSAP384SHA384")
            algs.add(INDIRECT, "INDIRECT")
            algs.add(PRIVATEDNS, "PRIVATEDNS")
            algs.add(PRIVATEOID, "PRIVATEOID")
        }

        /**
         * Converts an algorithm into its textual representation
         */
        fun string(alg: Int): String {
            return algs.getText(alg)
        }

        /**
         * Converts a textual representation of an algorithm into its numeric
         * code.  Integers in the range 0..255 are also accepted.
         *
         * @param s The textual representation of the algorithm
         *
         * @return The algorithm code, or -1 on error.
         */
        fun value(s: String): Int {
            return algs.getValue(s)
        }
    }

    /**
     * A DNSSEC exception.
     */
    open class DNSSECException internal constructor(s: String) : Exception(s)

    /**
     * An algorithm is unsupported by this DNSSEC implementation.
     */
    class UnsupportedAlgorithmException internal constructor(alg: Int) : DNSSECException("Unsupported algorithm: $alg")

    /**
     * The cryptographic data in a DNSSEC key is malformed.
     */
    class MalformedKeyException internal constructor(rec: KEYBase) : DNSSECException("Invalid key data: " + asString(rec)) {
        companion object {
            private fun asString(rec: KEYBase): String {
                val stringBuilder = StringBuilder()
                rec.rdataToString(stringBuilder)
                return stringBuilder.toString()
            }
        }
    }

    /**
     * A DNSSEC verification failed because fields in the DNSKEY and RRSIG records
     * do not match.
     */
    class KeyMismatchException internal constructor(key: KEYBase, sig: SIGBase) : DNSSECException(
        "key " + key.name + "/" + Algorithm.string(key.algorithm) + "/" + key.footprint + " " + "does not match signature " + sig.signer + "/" + Algorithm.string(sig.algorithm) + "/" + sig.footprint
    ) {
        private val key: KEYBase? = null
        private val sig: SIGBase? = null
    }

    /**
     * A DNSSEC verification failed because the signature has expired.
     */
    class SignatureExpiredException internal constructor(
        /**
         * @return When the signature expired
         */
        val expiration: Date,

        /**
         * @return When the verification was attempted
         */
        val verifyTime: Date
    ) : DNSSECException("signature expired")

    /**
     * A DNSSEC verification failed because the signature has not yet become valid.
     */
    class SignatureNotYetValidException internal constructor(
        /**
         * @return When the signature will become valid
         */
        val expiration: Date,
        /**
         * @return When the verification was attempted
         */
        val verifyTime: Date
    ) : DNSSECException("signature is not yet valid")

    /**
     * A DNSSEC verification failed because the cryptographic signature
     * verification failed.
     */
    class SignatureVerificationException internal constructor() : DNSSECException("signature verification failed")

    /**
     * The key data provided is inconsistent.
     */
    class IncompatibleKeyException internal constructor() : IllegalArgumentException("incompatible keys")

    /**
     * No signature was found.
     */
    class NoSignatureException internal constructor() : DNSSECException("no signature found")
    private class ECKeyInfo internal constructor(
        var length: Int,
        p_str: String?,
        a_str: String?,
        b_str: String?,
        gx_str: String?,
        gy_str: String?,
        n_str: String?
    ) {
        var p: BigInteger
        var a: BigInteger
        var b: BigInteger
        var gx: BigInteger
        var gy: BigInteger
        var n: BigInteger
        var curve: EllipticCurve
        var spec: ECParameterSpec

        init {
            p = BigInteger(p_str, 16)
            a = BigInteger(a_str, 16)
            b = BigInteger(b_str, 16)
            gx = BigInteger(gx_str, 16)
            gy = BigInteger(gy_str, 16)
            n = BigInteger(n_str, 16)
            curve = EllipticCurve(ECFieldFp(p), a, b)
            spec = ECParameterSpec(curve, ECPoint(gx, gy), n, 1)
        }
    }
}
