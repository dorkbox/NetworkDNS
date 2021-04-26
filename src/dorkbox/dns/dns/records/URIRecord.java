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

import dorkbox.dns.dns.exceptions.TextParseException;
import dorkbox.dns.dns.utils.Tokenizer;
import dorkbox.dns.dns.Compression;
import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsRecordType;

/**
 * Uniform Resource Identifier (URI) DNS Resource Record
 *
 * @author Anthony Kirby
 * @see <a href="http://tools.ietf.org/html/draft-faltstrom-uri">http://tools.ietf.org/html/draft-faltstrom-uri</a>
 */

public
class URIRecord extends DnsRecord {

    private static final long serialVersionUID = 7955422413971804232L;

    private int priority, weight;
    private byte[] target;

    URIRecord() {
        target = new byte[] {};
    }

    @Override
    DnsRecord getObject() {
        return new URIRecord();
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
        priority = in.readU16();
        weight = in.readU16();
        target = in.readByteArray();
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        out.writeU16(priority);
        out.writeU16(weight);
        out.writeByteArray(target);
    }

    /**
     * Converts rdata to a String
     */
    @Override
    void rrToString(StringBuilder sb) {
        sb.append(priority + " ");
        sb.append(weight + " ");
        sb.append(byteArrayToString(target, true));
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        priority = st.getUInt16();
        weight = st.getUInt16();
        try {
            target = byteArrayFromString(st.getString());
        } catch (TextParseException e) {
            throw st.exception(e.getMessage());
        }
    }

    /**
     * Creates a URI Record from the given data
     *
     * @param priority The priority of this URI.  Records with lower priority
     *         are preferred.
     * @param weight The weight, used to select between records at the same
     *         priority.
     * @param target The host/port running the service
     */
    public
    URIRecord(Name name, int dclass, long ttl, int priority, int weight, String target) {
        super(name, DnsRecordType.URI, dclass, ttl);
        this.priority = checkU16("priority", priority);
        this.weight = checkU16("weight", weight);
        try {
            this.target = byteArrayFromString(target);
        } catch (TextParseException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    /**
     * Returns the priority
     */
    public
    int getPriority() {
        return priority;
    }

    /**
     * Returns the weight
     */
    public
    int getWeight() {
        return weight;
    }

    /**
     * Returns the target URI
     */
    public
    String getTarget() {
        return byteArrayToString(target, false);
    }

}
