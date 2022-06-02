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
 * Host Information - describes the CPU and OS of a host
 *
 * @author Brian Wellington
 */

public
class HINFORecord extends DnsRecord {

    private static final long serialVersionUID = -4732870630947452112L;

    private byte[] cpu, os;

    HINFORecord() {}

    @Override
    DnsRecord getObject() {
        return new HINFORecord();
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
        cpu = in.readCountedString();
        os = in.readCountedString();
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        out.writeCountedString(cpu);
        out.writeCountedString(os);
    }

    /**
     * Converts to a string
     */
    @Override
    void rrToString(StringBuilder sb) {
        sb.append(byteArrayToString(cpu, true));
        sb.append(" ");
        sb.append(byteArrayToString(os, true));
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        try {
            cpu = byteArrayFromString(st.getString());
            os = byteArrayFromString(st.getString());
        } catch (TextParseException e) {
            throw st.exception(e.getMessage());
        }
    }

    /**
     * Creates an HINFO Record from the given data
     *
     * @param cpu A string describing the host's CPU
     * @param os A string describing the host's OS
     *
     * @throws IllegalArgumentException One of the strings has invalid escapes
     */
    public
    HINFORecord(Name name, int dclass, long ttl, String cpu, String os) {
        super(name, DnsRecordType.HINFO, dclass, ttl);
        try {
            this.cpu = byteArrayFromString(cpu);
            this.os = byteArrayFromString(os);
        } catch (TextParseException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    /**
     * Returns the host's CPU
     */
    public
    String getCPU() {
        return byteArrayToString(cpu, false);
    }

    /**
     * Returns the host's OS
     */
    public
    String getOS() {
        return byteArrayToString(os, false);
    }

}
