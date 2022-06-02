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
 * NSAP Pointer Record  - maps a domain name representing an NSAP Address to
 * a hostname.
 *
 * @author Brian Wellington
 */
@Deprecated
public
class NSAP_PTRRecord extends SingleNameBase {

    private static final long serialVersionUID = 2386284746382064904L;

    NSAP_PTRRecord() {}

    @Override
    DnsRecord getObject() {
        return new NSAP_PTRRecord();
    }

    /**
     * Creates a new NSAP_PTR Record with the given data
     *
     * @param target The name of the host with this address
     */
    public
    NSAP_PTRRecord(Name name, int dclass, long ttl, Name target) {
        super(name, DnsRecordType.NSAP_PTR, dclass, ttl, target, "target");
    }

    /**
     * Gets the target of the NSAP_PTR Record
     */
    public
    Name getTarget() {
        return getSingleName();
    }

}
