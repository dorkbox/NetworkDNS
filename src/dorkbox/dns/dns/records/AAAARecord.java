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

import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.utils.Address;
import dorkbox.dns.dns.utils.Tokenizer;
import dorkbox.netUtil.IPv6;
import dorkbox.dns.dns.Compression;
import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsRecordType;

/**
 * IPv6 Address Record - maps a domain name to an IPv6 address
 *
 * @author Brian Wellington
 */

public
class AAAARecord extends DnsRecord {

    private static final long serialVersionUID = -4588601512069748050L;

    private byte[] address;

    AAAARecord() {}

    @Override
    DnsRecord getObject() {
        return new AAAARecord();
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
        address = in.readByteArray(16);
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        out.writeByteArray(address);
    }

    /**
     * Converts rdata to a String
     */
    @Override
    void rrToString(StringBuilder sb) {
        InetAddress addr;
        try {
            addr = InetAddress.getByAddress(null, address);
        } catch (UnknownHostException e) {
            return;
        }
        if (addr.getAddress().length == 4) {
            // Deal with Java's broken handling of mapped IPv4 addresses.
            sb.append("0:0:0:0:0:ffff:");
            int high = ((address[12] & 0xFF) << 8) + (address[13] & 0xFF);
            int low = ((address[14] & 0xFF) << 8) + (address[15] & 0xFF);
            sb.append(Integer.toHexString(high));
            sb.append(':');
            sb.append(Integer.toHexString(low));

            return;
        }

        sb.append(addr.getHostAddress());
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        address = st.getAddressBytes(Address.IPv6);
    }

    /**
     * Creates an AAAA Record from the given data
     *
     * @param address The address that the name refers
     */
    public
    AAAARecord(Name name, int dclass, long ttl, InetAddress address) {
        super(name, DnsRecordType.AAAA, dclass, ttl);
        if (!IPv6.INSTANCE.isFamily(address)) {
            throw new IllegalArgumentException("invalid IPv6 address");
        }
        this.address = address.getAddress();
    }

    /**
     * Creates an AAAA Record from the given data
     *
     * @param address The address that the name refers to as a byte array. This value is NOT COPIED.
     */
    public
    AAAARecord(Name name, int dclass, long ttl, byte[] address) {
        super(name, DnsRecordType.AAAA, dclass, ttl);
        if ( address.length != IPv6.INSTANCE.getLength()) {
            throw new IllegalArgumentException("invalid IPv6 address");
        }
        this.address = address;
    }

    /**
     * Returns the address
     */
    public
    InetAddress getAddress() {
        try {
            if (name == null) {
                return InetAddress.getByAddress(address);
            }
            else {
                return InetAddress.getByAddress(name.toString(true), address);
            }
        } catch (UnknownHostException e) {
            return null;
        }
    }
}
