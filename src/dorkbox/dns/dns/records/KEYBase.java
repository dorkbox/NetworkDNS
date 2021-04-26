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
import java.security.PublicKey;
import java.util.Base64;

import dorkbox.dns.dns.utils.Options;
import dorkbox.dns.dns.Compression;
import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.Name;
import dorkbox.os.OS;

/**
 * The base class for KEY/DNSKEY records, which have identical formats
 *
 * @author Brian Wellington
 */

abstract
class KEYBase extends DnsRecord {

    private static final long serialVersionUID = 3469321722693285454L;

    protected int flags, proto, alg;
    protected byte[] key;
    protected int footprint = -1;
    protected PublicKey publicKey = null;

    protected
    KEYBase() {}

    public
    KEYBase(Name name, int type, int dclass, long ttl, int flags, int proto, int alg, byte[] key) {
        super(name, type, dclass, ttl);
        this.flags = checkU16("flags", flags);
        this.proto = checkU8("proto", proto);
        this.alg = checkU8("alg", alg);
        this.key = key;
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
        flags = in.readU16();
        proto = in.readU8();
        alg = in.readU8();
        if (in.remaining() > 0) {
            key = in.readByteArray();
        }
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        out.writeU16(flags);
        out.writeU8(proto);
        out.writeU8(alg);
        if (key != null) {
            out.writeByteArray(key);
        }
    }

    /**
     * Converts the DNSKEY/KEY Record to a String
     */
    @Override
    void rrToString(StringBuilder sb) {
        sb.append(flags);
        sb.append(" ");
        sb.append(proto);
        sb.append(" ");
        sb.append(alg);

        if (key != null) {
            if (Options.check("multiline")) {
                sb.append(" (");
                sb.append(OS.LINE_SEPARATOR);
                sb.append(Base64.getMimeEncoder().encodeToString(key));
                sb.append(OS.LINE_SEPARATOR);
                sb.append(") ; key_tag = ");
                sb.append(getFootprint());
            }
            else {
                sb.append(" ");
                sb.append(Base64.getEncoder().encodeToString(key));
            }
        }
    }

    /**
     * Returns the key's footprint (after computing it)
     */
    public
    int getFootprint() {
        if (footprint >= 0) {
            return footprint;
        }

        int foot = 0;

        DnsOutput out = new DnsOutput();
        rrToWire(out, null, false);
        byte[] rdata = out.toByteArray();

        if (alg == DNSSEC.Algorithm.RSAMD5) {
            int d1 = rdata[rdata.length - 3] & 0xFF;
            int d2 = rdata[rdata.length - 2] & 0xFF;
            foot = (d1 << 8) + d2;
        }
        else {
            int i;
            for (i = 0; i < rdata.length - 1; i += 2) {
                int d1 = rdata[i] & 0xFF;
                int d2 = rdata[i + 1] & 0xFF;
                foot += ((d1 << 8) + d2);
            }
            if (i < rdata.length) {
                int d1 = rdata[i] & 0xFF;
                foot += (d1 << 8);
            }
            foot += ((foot >> 16) & 0xFFFF);
        }
        footprint = (foot & 0xFFFF);
        return footprint;
    }

    /**
     * Returns the flags describing the key's properties
     */
    public
    int getFlags() {
        return flags;
    }

    /**
     * Returns the protocol that the key was created for
     */
    public
    int getProtocol() {
        return proto;
    }

    /**
     * Returns the key's algorithm
     */
    public
    int getAlgorithm() {
        return alg;
    }

    /**
     * Returns the binary data representing the key
     */
    public
    byte[] getKey() {
        return key;
    }

    /**
     * Returns a PublicKey corresponding to the data in this key.
     *
     * @throws DNSSEC.DNSSECException The key could not be converted.
     */
    public
    PublicKey getPublicKey() throws DNSSEC.DNSSECException {
        if (publicKey != null) {
            return publicKey;
        }

        publicKey = DNSSEC.toPublicKey(this);
        return publicKey;
    }

}
