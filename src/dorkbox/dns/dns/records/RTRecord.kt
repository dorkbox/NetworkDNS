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
 * Route Through Record - lists a route preference and intermediate host.
 *
 * @author Brian Wellington
 */

public
class RTRecord extends U16NameBase {

    private static final long serialVersionUID = -3206215651648278098L;

    RTRecord() {}

    @Override
    DnsRecord getObject() {
        return new RTRecord();
    }

    /**
     * Creates an RT Record from the given data
     *
     * @param preference The preference of the route.  Smaller numbers indicate
     *         more preferred routes.
     * @param intermediateHost The domain name of the host to use as a router.
     */
    public
    RTRecord(Name name, int dclass, long ttl, int preference, Name intermediateHost) {
        super(name, DnsRecordType.RT, dclass, ttl, preference, "preference", intermediateHost, "intermediateHost");
    }

    /**
     * Gets the preference of the route.
     */
    public
    int getPreference() {
        return getU16Field();
    }

    /**
     * Gets the host to use as a router.
     */
    public
    Name getIntermediateHost() {
        return getNameField();
    }

}
