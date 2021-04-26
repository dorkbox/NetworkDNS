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

package dorkbox.dns.dns.utils;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

import dorkbox.dns.DnsClient;
import dorkbox.dns.dns.records.PTRRecord;
import dorkbox.netUtil.dnsUtils.ResolvedAddressTypes;
import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsRecordType;
import dorkbox.dns.dns.records.DnsRecord;

/**
 * Routines dealing with IP addresses.  Includes functions similar to
 * those in the java.net.InetAddress class.
 *
 * @author Brian Wellington
 */

public final
class Address {

    public static final int IPv4 = 1;
    public static final int IPv6 = 2;

    private
    Address() {}

    /**
     * Determines the IP address of a host
     *
     * @param name The hostname to look up
     *
     * @return The first matching IP address or null
     *
     * @throws UnknownHostException The hostname does not have any addresses
     */
    public static
    InetAddress getByName(String name) throws UnknownHostException {
        // are we ALREADY IPv 4/6
        if (dorkbox.netUtil.IPv4.INSTANCE.isValid(name)) {
            return dorkbox.netUtil.IPv4.INSTANCE.toAddress(name);
        }
        if (dorkbox.netUtil.IPv6.INSTANCE.isValid(name)) {
            return dorkbox.netUtil.IPv6.INSTANCE.toAddress(name);
        }

        DnsClient client = new DnsClient();
        List<InetAddress> records = client.resolve(name);
        client.stop();
        return records.get(0);
    }

    /**
     * Determines all IP address of a host
     *
     * @param name The hostname to look up
     *
     * @return All matching IP addresses or null
     *
     * @throws UnknownHostException The hostname does not have any addresses
     */
    public static
    InetAddress[] getAllByName(String name) throws UnknownHostException {
        // are we ALREADY IPv 4/6
        if (dorkbox.netUtil.IPv4.INSTANCE.isValid(name)) {
            return new InetAddress[] {dorkbox.netUtil.IPv4.INSTANCE.toAddress(name)};
        }
        if (dorkbox.netUtil.IPv6.INSTANCE.isValid(name)) {
            return new InetAddress[] {dorkbox.netUtil.IPv6.INSTANCE.toAddress(name)};
        }


        List<InetAddress> combined = new ArrayList<InetAddress>();
        DnsClient client = new DnsClient();
        // ipv4
        client.resolvedAddressTypes(ResolvedAddressTypes.IPV4_ONLY);
        List<InetAddress> resolved = client.resolve(name);
        combined.addAll(resolved);
        client.stop();

        // ipv6
        client = new DnsClient();
        client.resolvedAddressTypes(ResolvedAddressTypes.IPV6_ONLY);
        resolved = client.resolve(name);
        client.stop();
        combined.addAll(resolved);

        return combined.toArray(new InetAddress[0]);
    }

    /**
     * Determines the hostname for an address
     *
     * @param addr The address to look up
     *
     * @return The associated host name
     *
     * @throws UnknownHostException There is no hostname for the address
     */
    public static
    String getHostName(InetAddress addr) throws UnknownHostException {
        Name name = ReverseMap.fromAddress(addr);

        DnsClient client = new DnsClient();
        client.resolvedAddressTypes(ResolvedAddressTypes.IPV4_ONLY);
        DnsRecord[] records;
        try {
            records = client.query(name.toString(true), DnsRecordType.PTR);
        } catch (Throwable ignored) {
            throw new UnknownHostException("unknown address");
        } finally {
            client.stop();
        }

        if (records == null) {
            throw new UnknownHostException("unknown address");
        }

        PTRRecord ptr = (PTRRecord) records[0];
        return ptr.getTarget()
                  .toString();
    }

    /**
     * Returns the family of an InetAddress.
     *
     * @param address The supplied address.
     *
     * @return The family, either IPv4 or IPv6.
     */
    public static
    int familyOf(InetAddress address) {
        if (address instanceof Inet4Address) {
            return IPv4;
        }

        if (address instanceof Inet6Address) {
            return IPv6;
        }
        throw new IllegalArgumentException("unknown address family");
    }
}
