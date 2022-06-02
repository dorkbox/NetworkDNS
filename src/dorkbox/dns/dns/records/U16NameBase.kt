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

/**
 * Implements common functionality for the many record types whose format
 * is an unsigned 16 bit integer followed by a name.
 *
 * @author Brian Wellington
 */

abstract
class U16NameBase extends DnsRecord {

    private static final long serialVersionUID = -8315884183112502995L;

    protected int u16Field;
    protected Name nameField;

    protected
    U16NameBase() {}

    protected
    U16NameBase(Name name, int type, int dclass, long ttl) {
        super(name, type, dclass, ttl);
    }

    protected
    U16NameBase(Name name, int type, int dclass, long ttl, int u16Field, String u16Description, Name nameField, String nameDescription) {
        super(name, type, dclass, ttl);
        this.u16Field = checkU16(u16Description, u16Field);
        this.nameField = checkName(nameDescription, nameField);
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
        u16Field = in.readU16();
        nameField = new Name(in);
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        out.writeU16(u16Field);
        nameField.toWire(out, null, canonical);
    }

    @Override
    void rrToString(StringBuilder sb) {
        sb.append(u16Field);
        sb.append(" ");
        sb.append(nameField);
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        u16Field = st.getUInt16();
        nameField = st.getName(origin);
    }

    protected
    int getU16Field() {
        return u16Field;
    }

    protected
    Name getNameField() {
        return nameField;
    }

}
