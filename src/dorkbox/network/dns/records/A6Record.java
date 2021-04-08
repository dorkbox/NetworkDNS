// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package dorkbox.network.dns.records;

import java.io.IOException;
import java.net.InetAddress;

import dorkbox.netUtil.IPv6;
import dorkbox.network.dns.Compression;
import dorkbox.network.dns.DnsInput;
import dorkbox.network.dns.DnsOutput;
import dorkbox.network.dns.Name;
import dorkbox.network.dns.constants.DnsRecordType;
import dorkbox.network.dns.utils.Tokenizer;

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
            suffix = IPv6.INSTANCE.toAddress(s);
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
