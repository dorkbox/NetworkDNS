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

import dorkbox.dns.dns.utils.Tokenizer;
import dorkbox.dns.dns.Compression;
import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.Name;

/**
 * A class implementing Records of unknown and/or unimplemented types.  This
 * class can only be initialized using static Record initializers.
 *
 * @author Brian Wellington
 */

public
class UNKRecord extends DnsRecord {

    private static final long serialVersionUID = -4193583311594626915L;

    private byte[] data;

    UNKRecord() {}

    @Override
    DnsRecord getObject() {
        return new UNKRecord();
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
        data = in.readByteArray();
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        out.writeByteArray(data);
    }

    /**
     * Converts this Record to the String "unknown format"
     */
    @Override
    void rrToString(StringBuilder sb) {
        sb.append(unknownToString(data));
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        throw st.exception("invalid unknown RR encoding");
    }

    /**
     * Returns the contents of this record.
     */
    public
    byte[] getData() {
        return data;
    }

}
