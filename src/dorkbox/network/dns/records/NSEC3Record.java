// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package dorkbox.network.dns.records;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import dorkbox.network.dns.Compression;
import dorkbox.network.dns.DnsInput;
import dorkbox.network.dns.DnsOutput;
import dorkbox.network.dns.Name;
import dorkbox.network.dns.constants.DnsRecordType;
import dorkbox.network.dns.utils.Tokenizer;
import dorkbox.network.dns.utils.base16;
import dorkbox.network.dns.utils.base32;

/**
 * Next SECure name 3 - this record contains the next hashed name in an
 * ordered list of hashed names in the zone, and a set of types for which
 * records exist for this name. The presence of this record in a response
 * signifies a negative response from a DNSSEC-signed zone.
 * <p>
 * This replaces the NSEC and NXT records, when used.
 *
 * @author Brian Wellington
 * @author David Blacka
 */

public
class NSEC3Record extends DnsRecord {

    public static final int SHA1_DIGEST_ID = Digest.SHA1;
    private static final long serialVersionUID = -7123504635968932855L;
    private int hashAlg;
    private int flags;
    private int iterations;
    private byte[] salt;
    private byte[] next;
    private TypeBitmap types;
    private static final base32 b32 = new base32(base32.Alphabet.BASE32HEX, false, false);


    public static
    class Flags {
        /**
         * Unsigned delegation are not included in the NSEC3 chain.
         */
        public static final int OPT_OUT = 0x01;

        /**
         * NSEC3 flags identifiers.
         */

        private
        Flags() {}
    }


    public static
    class Digest {
        /**
         * SHA-1
         */
        public static final int SHA1 = 1;

        private
        Digest() {}
    }

    NSEC3Record() {}

    @Override
    DnsRecord getObject() {
        return new NSEC3Record();
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
        hashAlg = in.readU8();
        flags = in.readU8();
        iterations = in.readU16();

        int salt_length = in.readU8();
        if (salt_length > 0) {
            salt = in.readByteArray(salt_length);
        }
        else {
            salt = null;
        }

        int next_length = in.readU8();
        next = in.readByteArray(next_length);
        types = new TypeBitmap(in);
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        out.writeU8(hashAlg);
        out.writeU8(flags);
        out.writeU16(iterations);

        if (salt != null) {
            out.writeU8(salt.length);
            out.writeByteArray(salt);
        }
        else {
            out.writeU8(0);
        }

        out.writeU8(next.length);
        out.writeByteArray(next);
        types.toWire(out);
    }

    /**
     * Converts rdata to a String
     */
    @Override
    void rrToString(StringBuilder sb) {
        sb.append(hashAlg);
        sb.append(' ');
        sb.append(flags);
        sb.append(' ');
        sb.append(iterations);
        sb.append(' ');

        if (salt == null) {
            sb.append('-');
        }
        else {
            sb.append(base16.toString(salt));
        }

        sb.append(' ');
        sb.append(b32.toString(next));

        if (!types.empty()) {
            sb.append(' ');
            sb.append(types.toString());
        }
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        hashAlg = st.getUInt8();
        flags = st.getUInt8();
        iterations = st.getUInt16();

        String s = st.getString();
        if (s.equals("-")) {
            salt = null;
        }
        else {
            st.unget();
            salt = st.getHexString();
            if (salt.length > 255) {
                throw st.exception("salt value too long");
            }
        }

        next = st.getBase32String(b32);
        types = new TypeBitmap(st);
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
    public
    NSEC3Record(Name name, int dclass, long ttl, int hashAlg, int flags, int iterations, byte[] salt, byte[] next, int[] types) {
        super(name, DnsRecordType.NSEC3, dclass, ttl);
        this.hashAlg = checkU8("hashAlg", hashAlg);
        this.flags = checkU8("flags", flags);
        this.iterations = checkU16("iterations", iterations);

        if (salt != null) {
            if (salt.length > 255) {
                throw new IllegalArgumentException("Invalid salt");
            }
            if (salt.length > 0) {
                this.salt = new byte[salt.length];
                System.arraycopy(salt, 0, this.salt, 0, salt.length);
            }
        }

        if (next.length > 255) {
            throw new IllegalArgumentException("Invalid next hash");
        }
        this.next = new byte[next.length];
        System.arraycopy(next, 0, this.next, 0, next.length);
        this.types = new TypeBitmap(types);
    }

    /**
     * Returns the hash algorithm
     */
    public
    int getHashAlgorithm() {
        return hashAlg;
    }

    /**
     * Returns the flags
     */
    public
    int getFlags() {
        return flags;
    }

    /**
     * Returns the number of iterations
     */
    public
    int getIterations() {
        return iterations;
    }

    /**
     * Returns the salt
     */
    public
    byte[] getSalt() {
        return salt;
    }

    /**
     * Returns the next hash
     */
    public
    byte[] getNext() {
        return next;
    }

    /**
     * Returns the set of types defined for this name
     */
    public
    int[] getTypes() {
        return types.toArray();
    }

    /**
     * Returns whether a specific type is in the set of types.
     */
    public
    boolean hasType(int type) {
        return types.contains(type);
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
    public
    byte[] hashName(Name name) throws NoSuchAlgorithmException {
        return hashName(name, hashAlg, iterations, salt);
    }

    static
    byte[] hashName(Name name, int hashAlg, int iterations, byte[] salt) throws NoSuchAlgorithmException {
        MessageDigest digest;
        switch (hashAlg) {
            case Digest.SHA1:
                digest = MessageDigest.getInstance("sha-1");
                break;
            default:
                throw new NoSuchAlgorithmException("Unknown NSEC3 algorithm" + "identifier: " + hashAlg);
        }
        byte[] hash = null;
        for (int i = 0; i <= iterations; i++) {
            digest.reset();
            if (i == 0) {
                digest.update(name.toWireCanonical());
            }
            else {
                digest.update(hash);
            }
            if (salt != null) {
                digest.update(salt);
            }
            hash = digest.digest();
        }
        return hash;
    }

}
