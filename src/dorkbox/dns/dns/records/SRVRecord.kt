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
 * Server Selection Record  - finds hosts running services in a domain.  An
 * SRV record will normally be named _&lt;service&gt;._&lt;protocol&gt;.domain
 * - examples would be _sips._tcp.example.org (for the secure SIP protocol) and
 * _http._tcp.example.com (if HTTP used SRV records)
 *
 * @author Brian Wellington
 */

public
class SRVRecord extends DnsRecord {

    private static final long serialVersionUID = -3886460132387522052L;

    private int priority, weight, port;
    private Name target;

    SRVRecord() {}

    @Override
    DnsRecord getObject() {
        return new SRVRecord();
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
        priority = in.readU16();
        weight = in.readU16();
        port = in.readU16();
        target = new Name(in);
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        out.writeU16(priority);
        out.writeU16(weight);
        out.writeU16(port);
        target.toWire(out, null, canonical);
    }

    /**
     * Converts rdata to a String
     */
    @Override
    void rrToString(StringBuilder sb) {
        sb.append(priority + " ");
        sb.append(weight + " ");
        sb.append(port + " ");
        sb.append(target);
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        priority = st.getUInt16();
        weight = st.getUInt16();
        port = st.getUInt16();
        target = st.getName(origin);
    }

    @Override
    public
    Name getAdditionalName() {
        return target;
    }

    /**
     * Creates an SRV Record from the given data
     *
     * @param priority The priority of this SRV.  Records with lower priority
     *         are preferred.
     * @param weight The weight, used to select between records at the same
     *         priority.
     * @param port The TCP/UDP port that the service uses
     * @param target The host running the service
     */
    public
    SRVRecord(Name name, int dclass, long ttl, int priority, int weight, int port, Name target) {
        super(name, DnsRecordType.SRV, dclass, ttl);
        this.priority = checkU16("priority", priority);
        this.weight = checkU16("weight", weight);
        this.port = checkU16("port", port);
        this.target = checkName("target", target);
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
     * Returns the port that the service runs on
     */
    public
    int getPort() {
        return port;
    }

    /**
     * Returns the host running that the service
     */
    public
    Name getTarget() {
        return target;
    }

}
