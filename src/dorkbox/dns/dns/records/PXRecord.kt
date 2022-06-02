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
 * X.400 mail mapping record.
 *
 * @author Brian Wellington
 */

public
class PXRecord extends DnsRecord {

    private static final long serialVersionUID = 1811540008806660667L;

    private int preference;
    private Name map822;
    private Name mapX400;

    PXRecord() {}

    @Override
    DnsRecord getObject() {
        return new PXRecord();
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
        preference = in.readU16();
        map822 = new Name(in);
        mapX400 = new Name(in);
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        out.writeU16(preference);
        map822.toWire(out, null, canonical);
        mapX400.toWire(out, null, canonical);
    }

    /**
     * Converts the PX Record to a String
     */
    @Override
    void rrToString(StringBuilder sb) {
        sb.append(preference);
        sb.append(" ");
        sb.append(map822);
        sb.append(" ");
        sb.append(mapX400);
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        preference = st.getUInt16();
        map822 = st.getName(origin);
        mapX400 = st.getName(origin);
    }

    /**
     * Creates an PX Record from the given data
     *
     * @param preference The preference of this mail address.
     * @param map822 The RFC 822 component of the mail address.
     * @param mapX400 The X.400 component of the mail address.
     */
    public
    PXRecord(Name name, int dclass, long ttl, int preference, Name map822, Name mapX400) {
        super(name, DnsRecordType.PX, dclass, ttl);

        this.preference = checkU16("preference", preference);
        this.map822 = checkName("map822", map822);
        this.mapX400 = checkName("mapX400", mapX400);
    }

    /**
     * Gets the preference of the route.
     */
    public
    int getPreference() {
        return preference;
    }

    /**
     * Gets the RFC 822 component of the mail address.
     */
    public
    Name getMap822() {
        return map822;
    }

    /**
     * Gets the X.400 component of the mail address.
     */
    public
    Name getMapX400() {
        return mapX400;
    }

}
