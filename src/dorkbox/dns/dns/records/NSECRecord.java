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
import dorkbox.dns.dns.constants.DnsRecordType;

/**
 * Next SECure name - this record contains the following name in an
 * ordered list of names in the zone, and a set of types for which
 * records exist for this name.  The presence of this record in a response
 * signifies a negative response from a DNSSEC-signed zone.
 * <p>
 * This replaces the NXT record.
 *
 * @author Brian Wellington
 * @author David Blacka
 */

public
class NSECRecord extends DnsRecord {

    private static final long serialVersionUID = -5165065768816265385L;

    private Name next;
    private TypeBitmap types;

    NSECRecord() {}

    @Override
    DnsRecord getObject() {
        return new NSECRecord();
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
        next = new Name(in);
        types = new TypeBitmap(in);
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        // Note: The next name is not lowercased.
        next.toWire(out, null, false);
        types.toWire(out);
    }

    /**
     * Converts rdata to a String
     */
    @Override
    void rrToString(StringBuilder sb) {
        sb.append(next);

        if (!types.empty()) {
            sb.append(' ');
            sb.append(types.toString());
        }
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        next = st.getName(origin);
        types = new TypeBitmap(st);
    }

    /**
     * Creates an NSEC Record from the given data.
     *
     * @param next The following name in an ordered list of the zone
     * @param types An array containing the types present.
     */
    public
    NSECRecord(Name name, int dclass, long ttl, Name next, int[] types) {
        super(name, DnsRecordType.NSEC, dclass, ttl);
        this.next = checkName("next", next);
        for (int i = 0; i < types.length; i++) {
            DnsRecordType.check(types[i]);
        }
        this.types = new TypeBitmap(types);
    }

    /**
     * Returns the next name
     */
    public
    Name getNext() {
        return next;
    }

    /**
     * Returns the set of types defined for this name
     */
    public
    int[] getTypes() {
        return types.toArray();
    }

    /**
     * Returns whether a specific type is in the set of types.
     */
    public
    boolean hasType(int type) {
        return types.contains(type);
    }

}
