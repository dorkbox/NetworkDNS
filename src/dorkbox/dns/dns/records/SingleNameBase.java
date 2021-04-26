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
import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.utils.Tokenizer;
import dorkbox.dns.dns.DnsOutput;

/**
 * Implements common functionality for the many record types whose format
 * is a single name.
 *
 * @author Brian Wellington
 */

abstract
class SingleNameBase extends DnsRecord {

    private static final long serialVersionUID = -18595042501413L;

    protected Name singleName;

    protected
    SingleNameBase() {}

    protected
    SingleNameBase(Name name, int type, int dclass, long ttl) {
        super(name, type, dclass, ttl);
    }

    protected
    SingleNameBase(Name name, int type, int dclass, long ttl, Name singleName, String description) {
        super(name, type, dclass, ttl);
        this.singleName = checkName(description, singleName);
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
        singleName = new Name(in);
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        singleName.toWire(out, null, canonical);
    }

    @Override
    void rrToString(StringBuilder sb) {
        sb.append(singleName.toString());
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        singleName = st.getName(origin);
    }

    protected
    Name getSingleName() {
        return singleName;
    }

}
