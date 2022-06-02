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

import dorkbox.dns.dns.exceptions.TextParseException;
import dorkbox.dns.dns.utils.Tokenizer;
import dorkbox.dns.dns.Compression;
import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsRecordType;

/**
 * Certification Authority Authorization
 *
 * @author Brian Wellington
 */

public
class CAARecord extends DnsRecord {

    private static final long serialVersionUID = 8544304287274216443L;
    private int flags;
    private byte[] tag;
    private byte[] value;


    public static
    class Flags {
        public static final int IssuerCritical = 128;

        private
        Flags() {}
    }

    CAARecord() {}

    @Override
    DnsRecord getObject() {
        return new CAARecord();
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
        flags = in.readU8();
        tag = in.readCountedString();
        value = in.readByteArray();
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        out.writeU8(flags);
        out.writeCountedString(tag);
        out.writeByteArray(value);
    }

    @Override
    void rrToString(StringBuilder sb) {
        sb.append(flags);
        sb.append(" ");
        sb.append(byteArrayToString(tag, false));
        sb.append(" ");
        sb.append(byteArrayToString(value, true));
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        flags = st.getUInt8();
        try {
            tag = byteArrayFromString(st.getString());
            value = byteArrayFromString(st.getString());
        } catch (TextParseException e) {
            throw st.exception(e.getMessage());
        }
    }

    /**
     * Creates an CAA Record from the given data.
     *
     * @param flags The flags.
     * @param tag The tag.
     * @param value The value.
     */
    public
    CAARecord(Name name, int dclass, long ttl, int flags, String tag, String value) {
        super(name, DnsRecordType.CAA, dclass, ttl);
        this.flags = checkU8("flags", flags);
        try {
            this.tag = byteArrayFromString(tag);
            this.value = byteArrayFromString(value);
        } catch (TextParseException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    /**
     * Returns the flags.
     */
    public
    int getFlags() {
        return flags;
    }

    /**
     * Returns the tag.
     */
    public
    String getTag() {
        return byteArrayToString(tag, false);
    }

    /**
     * Returns the value
     */
    public
    String getValue() {
        return byteArrayToString(value, false);
    }

}
