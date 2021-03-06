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
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Base64;

import dorkbox.dns.dns.exceptions.TextParseException;
import dorkbox.dns.dns.utils.Tokenizer;
import dorkbox.dns.dns.Compression;
import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsRecordType;
import dorkbox.dns.dns.exceptions.WireParseException;
import dorkbox.dns.dns.utils.Address;

/**
 * IPsec Keying Material (RFC 4025)
 *
 * @author Brian Wellington
 */

public
class IPSECKEYRecord extends DnsRecord {

    private static final long serialVersionUID = 3050449702765909687L;
    private int precedence;
    private int gatewayType;
    private int algorithmType;
    private Object gateway;
    private byte[] key;


    public static
    class Algorithm {
        public static final int DSA = 1;
        public static final int RSA = 2;
        private
        Algorithm() {}
    }


    public static
    class Gateway {
        public static final int None = 0;
        public static final int IPv4 = 1;
        public static final int IPv6 = 2;
        public static final int Name = 3;
        private
        Gateway() {}
    }

    IPSECKEYRecord() {}

    @Override
    DnsRecord getObject() {
        return new IPSECKEYRecord();
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
        precedence = in.readU8();
        gatewayType = in.readU8();
        algorithmType = in.readU8();
        switch (gatewayType) {
            case Gateway.None:
                gateway = null;
                break;
            case Gateway.IPv4:
                gateway = InetAddress.getByAddress(in.readByteArray(4));
                break;
            case Gateway.IPv6:
                gateway = InetAddress.getByAddress(in.readByteArray(16));
                break;
            case Gateway.Name:
                gateway = new Name(in);
                break;
            default:
                throw new WireParseException("invalid gateway type");
        }
        if (in.remaining() > 0) {
            key = in.readByteArray();
        }
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        out.writeU8(precedence);
        out.writeU8(gatewayType);
        out.writeU8(algorithmType);
        switch (gatewayType) {
            case Gateway.None:
                break;
            case Gateway.IPv4:
            case Gateway.IPv6:
                InetAddress gatewayAddr = (InetAddress) gateway;
                out.writeByteArray(gatewayAddr.getAddress());
                break;
            case Gateway.Name:
                Name gatewayName = (Name) gateway;
                gatewayName.toWire(out, null, canonical);
                break;
        }
        if (key != null) {
            out.writeByteArray(key);
        }
    }

    @Override
    void rrToString(StringBuilder sb) {
        sb.append(precedence);
        sb.append(" ");
        sb.append(gatewayType);
        sb.append(" ");
        sb.append(algorithmType);
        sb.append(" ");

        switch (gatewayType) {
            case Gateway.None:
                sb.append(".");
                break;
            case Gateway.IPv4:
            case Gateway.IPv6:
                InetAddress gatewayAddr = (InetAddress) gateway;
                sb.append(gatewayAddr.getHostAddress());
                break;
            case Gateway.Name:
                sb.append(gateway);
                break;
        }

        if (key != null) {
            sb.append(" ");
            sb.append(Base64.getEncoder().encodeToString(key));
        }
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        precedence = st.getUInt8();
        gatewayType = st.getUInt8();
        algorithmType = st.getUInt8();
        switch (gatewayType) {
            case Gateway.None:
                String s = st.getString();
                if (!s.equals(".")) {
                    throw new TextParseException("invalid gateway format");
                }
                gateway = null;
                break;
            case Gateway.IPv4:
                gateway = st.getAddress(Address.IPv4);
                break;
            case Gateway.IPv6:
                gateway = st.getAddress(Address.IPv6);
                break;
            case Gateway.Name:
                gateway = st.getName(origin);
                break;
            default:
                throw new WireParseException("invalid gateway type");
        }
        key = st.getBase64(false);
    }

    /**
     * Creates an IPSECKEY Record from the given data.
     *
     * @param precedence The record's precedence.
     * @param gatewayType The record's gateway type.
     * @param algorithmType The record's algorithm type.
     * @param gateway The record's gateway.
     * @param key The record's public key.
     */
    public
    IPSECKEYRecord(Name name, int dclass, long ttl, int precedence, int gatewayType, int algorithmType, Object gateway, byte[] key) {
        super(name, DnsRecordType.IPSECKEY, dclass, ttl);
        this.precedence = checkU8("precedence", precedence);
        this.gatewayType = checkU8("gatewayType", gatewayType);
        this.algorithmType = checkU8("algorithmType", algorithmType);
        switch (gatewayType) {
            case Gateway.None:
                this.gateway = null;
                break;
            case Gateway.IPv4:
                if (!(gateway instanceof InetAddress)) {
                    throw new IllegalArgumentException("\"gateway\" " + "must be an IPv4 " + "address");
                }
                this.gateway = gateway;
                break;
            case Gateway.IPv6:
                if (!(gateway instanceof Inet6Address)) {
                    throw new IllegalArgumentException("\"gateway\" " + "must be an IPv6 " + "address");
                }
                this.gateway = gateway;
                break;
            case Gateway.Name:
                if (!(gateway instanceof Name)) {
                    throw new IllegalArgumentException("\"gateway\" " + "must be a DNS " + "name");
                }
                this.gateway = checkName("gateway", (Name) gateway);
                break;
            default:
                throw new IllegalArgumentException("\"gatewayType\" " + "must be between 0 and 3");
        }

        this.key = key;
    }

    /**
     * Returns the record's precedence.
     */
    public
    int getPrecedence() {
        return precedence;
    }

    /**
     * Returns the record's gateway type.
     */
    public
    int getGatewayType() {
        return gatewayType;
    }

    /**
     * Returns the record's algorithm type.
     */
    public
    int getAlgorithmType() {
        return algorithmType;
    }

    /**
     * Returns the record's gateway.
     */
    public
    Object getGateway() {
        return gateway;
    }

    /**
     * Returns the record's public key
     */
    public
    byte[] getKey() {
        return key;
    }

}
