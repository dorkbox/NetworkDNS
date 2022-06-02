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

import java.util.List;

import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsRecordType;

/**
 * Text - stores text strings
 *
 * @author Brian Wellington
 */

public
class TXTRecord extends TXTBase {

    private static final long serialVersionUID = -5780785764284221342L;

    TXTRecord() {}

    @Override
    DnsRecord getObject() {
        return new TXTRecord();
    }

    /**
     * Creates a TXT Record from the given data
     *
     * @param strings The text strings
     *
     * @throws IllegalArgumentException One of the strings has invalid escapes
     */
    public
    TXTRecord(Name name, int dclass, long ttl, List<String> strings) {
        super(name, DnsRecordType.TXT, dclass, ttl, strings);
    }

    /**
     * Creates a TXT Record from the given data
     *
     * @param string One text string
     *
     * @throws IllegalArgumentException The string has invalid escapes
     */
    public
    TXTRecord(Name name, int dclass, long ttl, String string) {
        super(name, DnsRecordType.TXT, dclass, ttl, string);
    }

}
