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

package dorkbox.dns.dns.records;

import java.io.IOException;

import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.utils.Tokenizer;
import dorkbox.dns.dns.Compression;
import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsRecordType;
import dorkbox.dns.dns.utils.base16;

/**
 * DS - contains a Delegation Signer record, which acts as a
 * placeholder for KEY records in the parent zone.
 *
 * @author David Blacka
 * @author Brian Wellington
 * @see DNSSEC
 */

public
class DSRecord extends DnsRecord {

    public static final int SHA1_DIGEST_ID = Digest.SHA1;
    public static final int SHA256_DIGEST_ID = Digest.SHA256;
    public static final int GOST3411_DIGEST_ID = Digest.GOST3411;
    public static final int SHA384_DIGEST_ID = Digest.SHA384;
    private static final long serialVersionUID = -9001819329700081493L;
    private int footprint;
    private int alg;
    private int digestid;
    private byte[] digest;


    public static
    class Digest {
        /**
         * SHA-1
         */
        public static final int SHA1 = 1;
        /**
         * SHA-256
         */
        public static final int SHA256 = 2;
        /**
         * GOST R 34.11-94
         */
        public static final int GOST3411 = 3;
        /**
         * SHA-384
         */
        public static final int SHA384 = 4;

        private
        Digest() {}
    }

    DSRecord() {}

    @Override
    DnsRecord getObject() {
        return new DSRecord();
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
        footprint = in.readU16();
        alg = in.readU8();
        digestid = in.readU8();
        digest = in.readByteArray();
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        out.writeU16(footprint);
        out.writeU8(alg);
        out.writeU8(digestid);
        if (digest != null) {
            out.writeByteArray(digest);
        }
    }

    /**
     * Converts rdata to a String
     */
    @Override
    void rrToString(StringBuilder sb) {
        sb.append(footprint);
        sb.append(" ");
        sb.append(alg);
        sb.append(" ");
        sb.append(digestid);
        if (digest != null) {
            sb.append(" ");
            sb.append(base16.toString(digest));
        }
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        footprint = st.getUInt16();
        alg = st.getUInt8();
        digestid = st.getUInt8();
        digest = st.getHex();
    }

    /**
     * Creates a DS Record from the given data
     *
     * @param digestid The digest id code.
     * @param key The key to digest
     */
    public
    DSRecord(Name name, int dclass, long ttl, int digestid, DNSKEYRecord key) {
        this(name, dclass, ttl, key.getFootprint(), key.getAlgorithm(), digestid, DNSSEC.generateDSDigest(key, digestid));
    }

    /**
     * Creates a DS Record from the given data
     *
     * @param footprint The original KEY record's footprint (keyid).
     * @param alg The original key algorithm.
     * @param digestid The digest id code.
     * @param digest A hash of the original key.
     */
    public
    DSRecord(Name name, int dclass, long ttl, int footprint, int alg, int digestid, byte[] digest) {
        super(name, DnsRecordType.DS, dclass, ttl);
        this.footprint = checkU16("footprint", footprint);
        this.alg = checkU8("alg", alg);
        this.digestid = checkU8("digestid", digestid);
        this.digest = digest;
    }

    /**
     * Returns the key's algorithm.
     */
    public
    int getAlgorithm() {
        return alg;
    }

    /**
     * Returns the key's Digest ID.
     */
    public
    int getDigestID() {
        return digestid;
    }

    /**
     * Returns the binary hash of the key.
     */
    public
    byte[] getDigest() {
        return digest;
    }

    /**
     * Returns the key's footprint.
     */
    public
    int getFootprint() {
        return footprint;
    }

}
