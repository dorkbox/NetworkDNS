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
package dorkbox.dns.dns.utils

import dorkbox.dns.DnsClient
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.records.DnsRecord
import dorkbox.dns.dns.records.PTRRecord
import dorkbox.dns.dns.utils.ReverseMap.fromAddress
import dorkbox.netUtil.dnsUtils.ResolvedAddressTypes
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.UnknownHostException

/**
 * Routines dealing with IP addresses.  Includes functions similar to
 * those in the java.net.InetAddress class.
 *
 * @author Brian Wellington
 */
object Address {
    const val IPv4 = 1
    const val IPv6 = 2

    /**
     * Determines the IP address of a host
     *
     * @param name The hostname to look up
     *
     * @return The first matching IP address or null
     *
     * @throws UnknownHostException The hostname does not have any addresses
     */
    @Throws(UnknownHostException::class)
    fun getByName(name: String): InetAddress? {
        // are we ALREADY IPv 4/6
        if (dorkbox.netUtil.IPv4.isValid(name)) {
            return dorkbox.netUtil.IPv4.toAddress(name)
        }

        if (dorkbox.netUtil.IPv6.isValid(name)) {
            return dorkbox.netUtil.IPv6.toAddress(name)
        }

        val client = DnsClient()
        val records = client.resolve(name)
        client.stop()
        return records[0]
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
    @Throws(UnknownHostException::class)
    fun getAllByName(name: String): Array<InetAddress?> {
        // are we ALREADY IPv 4/6
        if (dorkbox.netUtil.IPv4.isValid(name)) {
            return arrayOf(dorkbox.netUtil.IPv4.toAddress(name))
        }

        if (dorkbox.netUtil.IPv6.isValid(name)) {
            return arrayOf(dorkbox.netUtil.IPv6.toAddress(name))
        }

        val combined: MutableList<InetAddress?> = ArrayList()
        var client = DnsClient()

        // ipv4
        client.resolvedAddressTypes(ResolvedAddressTypes.IPV4_ONLY)
        var resolved: List<InetAddress?> = client.resolve(name)
        combined.addAll(resolved)
        client.stop()

        // ipv6
        client = DnsClient()
        client.resolvedAddressTypes(ResolvedAddressTypes.IPV6_ONLY)
        resolved = client.resolve(name)
        client.stop()

        combined.addAll(resolved)
        return combined.toTypedArray()
    }

    /**
     * Determines the hostname for an address
     *
     * @param address The address to look up
     *
     * @return The associated host name
     *
     * @throws UnknownHostException There is no hostname for the address
     */
    @Throws(UnknownHostException::class)
    fun getHostName(address: InetAddress): String {
        val name = fromAddress(address)
        val client = DnsClient()
        client.resolvedAddressTypes(ResolvedAddressTypes.IPV4_ONLY)

        val records: Array<DnsRecord>
        records = try {
            client.query(name.toString(true), DnsRecordType.PTR)
        } catch (ignored: Throwable) {
            throw UnknownHostException("unknown address")
        } finally {
            client.stop()
        }

        if (records == null) {
            throw UnknownHostException("unknown address")
        }
        val ptr = records[0] as PTRRecord
        return ptr.target.toString()
    }

    /**
     * Returns the family of an InetAddress.
     *
     * @param address The supplied address.
     *
     * @return The family, either IPv4 or IPv6.
     */
    fun familyOf(address: InetAddress?): Int {
        if (address is Inet4Address) {
            return IPv4
        }
        if (address is Inet6Address) {
            return IPv6
        }
        throw IllegalArgumentException("unknown address family")
    }
}
