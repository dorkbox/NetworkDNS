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

import dorkbox.dns.dns.Compression;
import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsRecordType;
import dorkbox.dns.dns.utils.Options;
import dorkbox.dns.dns.utils.Tokenizer;
import dorkbox.os.OS;

/**
 * OPENPGPKEY Record - Stores an OpenPGP certificate associated with a name.
 * RFC 7929.
 *
 * @author Brian Wellington
 * @author Valentin Hauner
 */
public
class OPENPGPKEYRecord extends DnsRecord {

    private static final long serialVersionUID = -1277262990243423062L;

    private byte[] cert;

    OPENPGPKEYRecord() {}

    @Override
    DnsRecord getObject() {
        return new OPENPGPKEYRecord();
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
        cert = in.readByteArray();
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        out.writeByteArray(cert);
    }

    /**
     * Converts rdata to a String
     */
    @Override
    void rrToString(StringBuilder sb) {
        if (cert != null) {
            if (Options.check("multiline")) {
                sb.append(OS.INSTANCE.getLINE_SEPARATOR());
                sb.append(Base64.getEncoder().encodeToString(cert));
            }
            else {
                sb.append("\t");
                sb.append(Base64.getEncoder().encodeToString(cert));
            }
        }
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        cert = st.getBase64();
    }

    /**
     * Creates an OPENPGPKEY Record from the given data
     *
     * @param cert Binary data representing the certificate
     */
    public
    OPENPGPKEYRecord(Name name, int dclass, long ttl, byte[] cert) {
        super(name, DnsRecordType.OPENPGPKEY, dclass, ttl);
        this.cert = cert;
    }

    /**
     * Returns the binary representation of the certificate
     */
    public
    byte[] getCert() {
        return cert;
    }

}
