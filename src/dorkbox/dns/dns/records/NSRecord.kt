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
 * Name Server Record  - contains the name server serving the named zone
 *
 * @author Brian Wellington
 */

public
class NSRecord extends SingleCompressedNameBase {

    private static final long serialVersionUID = 487170758138268838L;

    NSRecord() {}

    @Override
    DnsRecord getObject() {
        return new NSRecord();
    }

    @Override
    public
    Name getAdditionalName() {
        return getSingleName();
    }

    /**
     * Creates a new NS Record with the given data
     *
     * @param target The name server for the given domain
     */
    public
    NSRecord(Name name, int dclass, long ttl, Name target) {
        super(name, DnsRecordType.NS, dclass, ttl, target, "target");
    }

    /**
     * Gets the target of the NS Record
     */
    public
    Name getTarget() {
        return getSingleName();
    }

}
