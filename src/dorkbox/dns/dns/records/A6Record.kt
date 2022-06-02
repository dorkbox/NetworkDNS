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
import java.net.InetAddress;

import dorkbox.dns.dns.utils.Tokenizer;
import dorkbox.netUtil.IPv6;
import dorkbox.dns.dns.Compression;
import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsRecordType;
import dorkbox.dns.dns.exceptions.TextParseException;

/**
 * A6 Record - maps a domain name to an IPv6 address (experimental)
 *
 * @author Brian Wellington
 */

public
class A6Record extends DnsRecord {

    private static final long serialVersionUID = -8815026887337346789L;

    private int prefixBits;
    private InetAddress suffix;
    private Name prefix;

    A6Record() {}

    @Override
    DnsRecord getObject() {
        return new A6Record();
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
        prefixBits = in.readU8();
        int suffixbits = 128 - prefixBits;
        int suffixbytes = (suffixbits + 7) / 8;
        if (prefixBits < 128) {
            byte[] bytes = new byte[16];
            in.readByteArray(bytes, 16 - suffixbytes, suffixbytes);
            suffix = InetAddress.getByAddress(bytes);
        }
        if (prefixBits > 0) {
            prefix = new Name(in);
        }
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        out.writeU8(prefixBits);
        if (suffix != null) {
            int suffixbits = 128 - prefixBits;
            int suffixbytes = (suffixbits + 7) / 8;
            byte[] data = suffix.getAddress();
            out.writeByteArray(data, 16 - suffixbytes, suffixbytes);
        }
        if (prefix != null) {
            prefix.toWire(out, null, canonical);
        }
    }

    /**
     * Converts rdata to a String
     */
    @Override
    void rrToString(StringBuilder sb) {
        sb.append(prefixBits);
        if (suffix != null) {
            sb.append(" ");
            sb.append(suffix.getHostAddress());
        }
        if (prefix != null) {
            sb.append(" ");
            sb.append(prefix);
        }
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        prefixBits = st.getUInt8();
        if (prefixBits > 128) {
            throw st.exception("prefix bits must be [0..128]");
        }
        else if (prefixBits < 128) {
            String s = st.getString();
            try {
                suffix = IPv6.INSTANCE.toAddress(s);
            } catch (Exception e) {
                throw new TextParseException("Invalid address: " + s, e);
            }
        }
        if (prefixBits > 0) {
            prefix = st.getName(origin);
        }
    }

    /**
     * Creates an A6 Record from the given data
     *
     * @param prefixBits The number of bits in the address prefix
     * @param suffix The address suffix
     * @param prefix The name of the prefix
     */
    public
    A6Record(Name name, int dclass, long ttl, int prefixBits, InetAddress suffix, Name prefix) {
        super(name, DnsRecordType.A6, dclass, ttl);
        this.prefixBits = checkU8("prefixBits", prefixBits);
        if (suffix != null && !IPv6.INSTANCE.isFamily(suffix)) {
            throw new IllegalArgumentException("invalid IPv6 address");
        }
        this.suffix = suffix;
        if (prefix != null) {
            this.prefix = checkName("prefix", prefix);
        }
    }

    /**
     * Returns the number of bits in the prefix
     */
    public
    int getPrefixBits() {
        return prefixBits;
    }

    /**
     * Returns the address suffix
     */
    public
    InetAddress getSuffix() {
        return suffix;
    }

    /**
     * Returns the address prefix
     */
    public
    Name getPrefix() {
        return prefix;
    }

}
