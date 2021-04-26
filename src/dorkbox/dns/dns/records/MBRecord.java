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
 * Mailbox Record  - specifies a host containing a mailbox.
 *
 * @author Brian Wellington
 */

public
class MBRecord extends SingleNameBase {

    private static final long serialVersionUID = 532349543479150419L;

    MBRecord() {}

    @Override
    DnsRecord getObject() {
        return new MBRecord();
    }

    @Override
    public
    Name getAdditionalName() {
        return getSingleName();
    }

    /**
     * Creates a new MB Record with the given data
     *
     * @param mailbox The host containing the mailbox for the domain.
     */
    public
    MBRecord(Name name, int dclass, long ttl, Name mailbox) {
        super(name, DnsRecordType.MB, dclass, ttl, mailbox, "mailbox");
    }

    /**
     * Gets the mailbox for the domain
     */
    public
    Name getMailbox() {
        return getSingleName();
    }

}
