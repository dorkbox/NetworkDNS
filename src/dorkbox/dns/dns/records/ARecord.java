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
import java.net.UnknownHostException;

import dorkbox.dns.dns.utils.Tokenizer;
import dorkbox.netUtil.IPv4;
import dorkbox.dns.dns.Compression;
import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsRecordType;
import dorkbox.dns.dns.utils.Address;

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
        IPv4.INSTANCE.toString(addr, sb);
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
        if (!IPv4.INSTANCE.isFamily(address)) {
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
        if (address.length != IPv4.INSTANCE.getLength()) {
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
