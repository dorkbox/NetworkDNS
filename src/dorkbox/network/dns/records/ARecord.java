// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package dorkbox.network.dns.records;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

import dorkbox.network.dns.Compression;
import dorkbox.network.dns.DnsInput;
import dorkbox.network.dns.DnsOutput;
import dorkbox.network.dns.Name;
import dorkbox.network.dns.constants.DnsRecordType;
import dorkbox.network.dns.utils.Address;
import dorkbox.network.dns.utils.Tokenizer;

/**
 * Address Record - maps a domain name to an Internet address
 *
 * @author Brian Wellington
 */

public
class ARecord extends DnsRecord {

    private static final long serialVersionUID = -2172609200849142323L;

    private int addr;

    ARecord() {}

    @Override
    DnsRecord getObject() {
        return new ARecord();
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
        addr = fromArray(in.readByteArray(4));
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        out.writeU32(((long) addr) & 0xFFFFFFFFL);
    }

    /**
     * Converts rdata to a String
     */
    @Override
    void rrToString(StringBuilder sb) {
        sb.append(Address.toDottedQuad(toArray(addr)));
    }

    private static
    byte[] toArray(int addr) {
        byte[] bytes = new byte[4];
        bytes[0] = (byte) ((addr >>> 24) & 0xFF);
        bytes[1] = (byte) ((addr >>> 16) & 0xFF);
        bytes[2] = (byte) ((addr >>> 8) & 0xFF);
        bytes[3] = (byte) (addr & 0xFF);
        return bytes;
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        addr = fromArray(st.getAddressBytes(Address.IPv4));
    }

    private static
    int fromArray(byte[] array) {
        return (((array[0] & 0xFF) << 24) | ((array[1] & 0xFF) << 16) | ((array[2] & 0xFF) << 8) | (array[3] & 0xFF));
    }

    /**
     * Creates an A Record from the given data
     *
     * @param address The address that the name refers to
     */
    public
    ARecord(Name name, int dclass, long ttl, InetAddress address) {
        super(name, DnsRecordType.A, dclass, ttl);
        if (Address.familyOf(address) != Address.IPv4) {
            throw new IllegalArgumentException("invalid IPv4 address");
        }
        addr = fromArray(address.getAddress());
    }

    /**
     * Creates an A Record from the given data
     *
     * @param address The address that the name refers to as a byte array. This value is NOT COPIED.
     */
    public
    ARecord(Name name, int dclass, long ttl, byte[] address) {
        super(name, DnsRecordType.A, dclass, ttl);
        if (address.length != Address.addressLength(Address.IPv4)) {
            throw new IllegalArgumentException("invalid IPv4 address");
        }
        addr = fromArray(address);
    }

    /**
     * Returns the Internet address
     */
    public
    InetAddress getAddress() {
        try {
            if (name == null) {
                return InetAddress.getByAddress(toArray(addr));
            }
            else {
                return InetAddress.getByAddress(name.toString(true), toArray(addr));
            }
        } catch (UnknownHostException e) {
            return null;
        }
    }
}
