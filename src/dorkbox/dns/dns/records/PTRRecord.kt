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

import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsRecordType;

/**
 * Pointer Record  - maps a domain name representing an Internet Address to
 * a hostname.
 *
 * @author Brian Wellington
 */

public
class PTRRecord extends SingleCompressedNameBase {

    private static final long serialVersionUID = -8321636610425434192L;

    PTRRecord() {}

    @Override
    DnsRecord getObject() {
        return new PTRRecord();
    }

    /**
     * Creates a new PTR Record with the given data
     *
     * @param target The name of the machine with this address
     */
    public
    PTRRecord(Name name, int dclass, long ttl, Name target) {
        super(name, DnsRecordType.PTR, dclass, ttl, target, "target");
    }

    /**
     * Gets the target of the PTR Record
     */
    public
    Name getTarget() {
        return getSingleName();
    }

}
