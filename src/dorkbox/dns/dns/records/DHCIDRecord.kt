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
import java.util.Base64;

import dorkbox.dns.dns.utils.Tokenizer;
import dorkbox.dns.dns.Compression;
import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsRecordType;

/**
 * DHCID - Dynamic Host Configuration Protocol (DHCP) ID (RFC 4701)
 *
 * @author Brian Wellington
 */

public
class DHCIDRecord extends DnsRecord {

    private static final long serialVersionUID = -8214820200808997707L;

    private byte[] data;

    DHCIDRecord() {}

    @Override
    DnsRecord getObject() {
        return new DHCIDRecord();
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
        data = in.readByteArray();
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        out.writeByteArray(data);
    }

    @Override
    void rrToString(StringBuilder sb) {
        sb.append(Base64.getEncoder().encodeToString(data));
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        data = st.getBase64();
    }

    /**
     * Creates an DHCID Record from the given data
     *
     * @param data The binary data, which is opaque to DNS.
     */
    public
    DHCIDRecord(Name name, int dclass, long ttl, byte[] data) {
        super(name, DnsRecordType.DHCID, dclass, ttl);
        this.data = data;
    }

    /**
     * Returns the binary data.
     */
    public
    byte[] getData() {
        return data;
    }

}
