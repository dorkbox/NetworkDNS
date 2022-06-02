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

import dorkbox.dns.dns.Compression;
import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.utils.Tokenizer;
import dorkbox.dns.dns.constants.DnsRecordType;
import dorkbox.dns.dns.utils.base16;

/**
 * SSH Fingerprint - stores the fingerprint of an SSH host key.
 *
 * @author Brian Wellington
 */

public
class SSHFPRecord extends DnsRecord {

    private static final long serialVersionUID = -8104701402654687025L;
    private int alg;
    private int digestType;
    private byte[] fingerprint;


    public static
    class Algorithm {
        public static final int RSA = 1;
        public static final int DSS = 2;
        private
        Algorithm() {}
    }


    public static
    class Digest {
        public static final int SHA1 = 1;

        private
        Digest() {}
    }

    SSHFPRecord() {}

    @Override
    DnsRecord getObject() {
        return new SSHFPRecord();
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
        alg = in.readU8();
        digestType = in.readU8();
        fingerprint = in.readByteArray();
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        out.writeU8(alg);
        out.writeU8(digestType);
        out.writeByteArray(fingerprint);
    }

    @Override
    void rrToString(StringBuilder sb) {
        sb.append(alg);
        sb.append(" ");
        sb.append(digestType);
        sb.append(" ");
        sb.append(base16.toString(fingerprint));
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        alg = st.getUInt8();
        digestType = st.getUInt8();
        fingerprint = st.getHex(true);
    }

    /**
     * Creates an SSHFP Record from the given data.
     *
     * @param alg The public key's algorithm.
     * @param digestType The public key's digest type.
     * @param fingerprint The public key's fingerprint.
     */
    public
    SSHFPRecord(Name name, int dclass, long ttl, int alg, int digestType, byte[] fingerprint) {
        super(name, DnsRecordType.SSHFP, dclass, ttl);
        this.alg = checkU8("alg", alg);
        this.digestType = checkU8("digestType", digestType);
        this.fingerprint = fingerprint;
    }

    /**
     * Returns the public key's algorithm.
     */
    public
    int getAlgorithm() {
        return alg;
    }

    /**
     * Returns the public key's digest type.
     */
    public
    int getDigestType() {
        return digestType;
    }

    /**
     * Returns the fingerprint
     */
    public
    byte[] getFingerPrint() {
        return fingerprint;
    }

}
