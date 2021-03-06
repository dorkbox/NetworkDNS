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

/**
 * X25 - identifies the PSDN (Public Switched Data Network) address in the
 * X.121 numbering plan associated with a name.
 *
 * @author Brian Wellington
 */

public
class X25Record extends DnsRecord {

    private static final long serialVersionUID = 4267576252335579764L;

    private byte[] address;

    X25Record() {}

    @Override
    DnsRecord getObject() {
        return new X25Record();
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
        address = in.readCountedString();
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        out.writeCountedString(address);
    }

    @Override
    void rrToString(StringBuilder sb) {
        sb.append(byteArrayToString(address, true));
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        String addr = st.getString();
        this.address = checkAndConvertAddress(addr);
        if (this.address == null) {
            throw st.exception("invalid PSDN address " + addr);
        }
    }

    /**
     * Creates an X25 Record from the given data
     *
     * @param address The X.25 PSDN address.
     *
     * @throws IllegalArgumentException The address is not a valid PSDN address.
     */
    public
    X25Record(Name name, int dclass, long ttl, String address) {
        super(name, DnsRecordType.X25, dclass, ttl);
        this.address = checkAndConvertAddress(address);
        if (this.address == null) {
            throw new IllegalArgumentException("invalid PSDN address " + address);
        }
    }

    private static
    byte[] checkAndConvertAddress(String address) {
        int length = address.length();
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            char c = address.charAt(i);
            if (!Character.isDigit(c)) {
                return null;
            }
            out[i] = (byte) c;
        }
        return out;
    }

    /**
     * Returns the X.25 PSDN address.
     */
    public
    String getAddress() {
        return byteArrayToString(address, false);
    }
}
