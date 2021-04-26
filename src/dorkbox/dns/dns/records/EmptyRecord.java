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
 * A class implementing Records with no data; that is, records used in
 * the question section of messages and meta-records in dynamic update.
 *
 * @author Brian Wellington
 */

class EmptyRecord extends DnsRecord {

    private static final long serialVersionUID = 3601852050646429582L;

    EmptyRecord() {}

    @Override
    DnsRecord getObject() {
        return new EmptyRecord();
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
    }

    @Override
    void rrToString(StringBuilder sb) {
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
    }
}
