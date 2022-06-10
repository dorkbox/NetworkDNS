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
package dorkbox.dns.dns.constants

import dorkbox.collections.IntMap
import dorkbox.dns.dns.Mnemonic
import dorkbox.dns.dns.exceptions.InvalidTypeException
import dorkbox.dns.dns.records.DnsRecord
import dorkbox.dns.dns.records.DnsTypeProtoAssignment

/**
 * Constants and functions relating to DNS Types
 *
 * @author Brian Wellington
 */
object DnsRecordType {
    /**
     * Address record RFC 1035 Returns a 32-bit IPv4 address, most commonly used
     * to map hostnames to an IP address of the host, but also used for DNSBLs,
     * storing subnet masks in RFC 1101, etc.
     */
    const val A = 1

    /**
     * Name server record RFC 1035 Delegates a DNS zone to use the given
     * authoritative name servers
     */
    const val NS = 2

    /**
     * Mail destination. MD specifies the final destination to which a message addressed to a given domain name should be delivered
     * (Obsolete, as it's behavior has been replaced by MX)
     */
    @Deprecated("Use MX instead")
    const val MD = 3

    /**
     * Mail forwarder. MF specifies a host that would forward mail on to the eventual destination, should that destination be unreachable.
     * (Obsolete, as it's behavior has been replaced by MX)
     */
    @Deprecated("Use MX instead")
    const val MF = 4

    /**
     * Canonical name (alias) record RFC 1035 Alias of one name to another: the DNS
     * lookup will continue by retrying the lookup with the new name.
     */
    const val CNAME = 5

    /**
     * Start of [a zone of] authority record RFC 1035 and RFC 2308 Specifies
     * authoritative information about a DNS zone, including the primary name
     * server, the email of the domain administrator, the domain serial number,
     * and several timers relating to refreshing the zone.
     */
    const val SOA = 6

    /**
     * Mailbox domain name RFC 1035. EXPERIMENTAL. A <domain-name> which specifies a host which has the
     * specified mailbox.
    </domain-name> */
    const val MB = 7

    /**
     * Mail group member RFC 1035. EXPERIMENTAL. A <domain-name> which specifies a mailbox which is a
     * member of the mail group specified by the domain name. MG records cause no additional section processing.
    </domain-name> */
    const val MG = 8

    /**
     * Mail rename name RFC 1035. EXPERIMENTAL. A <domain-name> which specifies a mailbox which is the
     * proper rename of the specified mailbox.
    </domain-name> */
    const val MR = 9

    /**
     * Null record RFC 1035. EXPERIMENTAL. Anything at all may be in the RDATA field so long as it is 65535 octets
     * or less
     */
    const val NULL = 10

    /**
     * The WKS record RFC 1035 is used to describe the well known services supported by
     * a particular protocol on a particular internet address.
     */
    const val WKS = 11

    /**
     * Pointer record RFC 1035 Pointer to a canonical name. Unlike a CNAME, DNS
     * processing does NOT proceed, just the name is returned. The most common
     * use is for implementing reverse DNS lookups, but other uses include such
     * things as DNS-SD.
     */
    const val PTR = 12

    /**
     * Host information HINFO RFC 1035. records are used to acquire general information about a host.  The
     * main use is for protocols such as FTP that can use special procedures when talking between machines
     * or operating systems of the same type.
     */
    const val HINFO = 13

    /**
     * Mailbox or mail list information RFC 1035. EXPERIMENTAL. MINFO records cause no additional section processing.  Although these
     * records can be associated with a simple mailbox, they are usually used with a mailing list.
     */
    const val MINFO = 14

    /**
     * Mail exchange (routing) record RFC 1035 Maps a domain name to a list of message transfer agents for that domain.
     */
    const val MX = 15

    /**
     * Text record RFC 1035 Originally for arbitrary human-readable text in a
     * DNS record. Since the early 1990s, however, this record more often
     * carries machine-readable data, such as specified by RFC 1464,
     * opportunistic encryption, Sender Policy Framework, DKIM, DMARC DNS-SD,
     * etc.
     */
    const val TXT = 16

    /**
     * Responsible person record RFC 1183 Information about the responsible
     * person(s) for the domain. Usually an email address with the @ replaced by
     * a .
     */
    const val RP = 17

    /**
     * AFS cell database record RFC 1183 Location of database servers of an AFS cell.
     * This record is commonly used by AFS clients to contact AFS cells outside
     * their local domain. A subtype of this record is used by the obsolete
     * DCE/DFS file system.
     */
    const val AFSDB = 18

    /**
     * X.25 calling address
     */
    const val X25 = 19

    /**
     * ISDN calling address
     */
    const val ISDN = 20

    /**
     * Router
     */
    const val RT = 21

    /**
     * NSAP address
     */
    const val NSAP = 22

    /**
     * Reverse NSAP address (deprecated)
     */
    @Deprecated("Don't use this anymore")
    const val NSAP_PTR = 23

    /**
     * Signature record RFC 2535 Signature record used in SIG(0) (RFC 2931) and
     * TKEY (RFC 2930). RFC 3755 designated RRSIG as the replacement for SIG for
     * use within DNSSEC.
     */
    const val SIG = 24

    /**
     * key record RFC 2535 and RFC 2930 Used only for SIG(0) (RFC 2931) and TKEY
     * (RFC 2930). RFC 3445 eliminated their use for application keys and
     * limited their use to DNSSEC. RFC 3755 designates DNSKEY as the
     * replacement within DNSSEC. RFC 4025 designates IPSECKEY as the
     * replacement for use with IPsec.
     */
    const val KEY = 25

    /**
     * X.400 mail mapping
     */
    const val PX = 26

    /**
     * Geographical position (withdrawn)
     */
    @Deprecated("This has been withdrawn")
    const val GPOS = 27

    /**
     * IPv6 address record RFC 3596 Returns a 128-bit IPv6 address, most
     * commonly used to map hostnames to an IP address of the host.
     */
    const val AAAA = 28

    /**
     * Location record RFC 1876 Specifies a geographical location associated
     * with a domain name.
     */
    const val LOC = 29

    /**
     * Next valid name in zone
     */
    const val NXT = 30

    /**
     * Endpoint identifier
     */
    const val EID = 31

    /**
     * Nimrod locator
     */
    const val NIMLOC = 32

    /**
     * Service selection locator RFC 2782 Generalized service location record, used for
     * newer protocols instead of creating protocol-specific records such as MX.
     */
    const val SRV = 33

    /**
     * ATM address
     */
    const val ATMA = 34

    /**
     * Naming Authority Pointer record RFC 3403 Allows regular expression based
     * rewriting of domain names which can then be used as URIs, further domain
     * names to lookups, etc.
     */
    const val NAPTR = 35

    /**
     * Key eXchanger record RFC 2230 Used with some cryptographic systems (not
     * including DNSSEC) to identify a key management agent for the associated
     * domain-name. Note that this has nothing to do with DNS Security. It is
     * Informational status, rather than being on the IETF standards-track. It
     * has always had limited deployment, but is still in use.
     */
    const val KX = 36

    /**
     * Certificate record RFC 4398 Stores PKIX, SPKI, PGP, etc.
     */
    const val CERT = 37

    /**
     * IPv6 address (experimental)
     */
    const val A6 = 38

    /**
     * Delegation name record RFC 2672 DNAME creates an alias for a name and all
     * its subnames, unlike CNAME, which aliases only the exact name in its
     * label. Like the CNAME record, the DNS lookup will continue by retrying
     * the lookup with the new name. This is also known as Non-terminal name redirection
     */
    const val DNAME = 39

    /**
     * Options - contains EDNS metadata. Option record RFC 2671 This is a pseudo DNS
     * record type needed to support EDNS.
     */
    const val OPT = 41

    /**
     * Address Prefix List record RFC 3123 Specify lists of address ranges, e.g.
     * in CIDR format, for various address families. Experimental.
     */
    const val APL = 42

    /**
     * Delegation signer record RFC 4034 The record used to identify the DNSSEC
     * signing key of a delegated zone.
     */
    const val DS = 43

    /**
     * SSH Public Key Fingerprint record RFC 4255 Resource record for publishing
     * SSH public host key fingerprints in the DNS System, in order to aid in
     * verifying the authenticity of the host. RFC 6594 defines ECC SSH keys and
     * SHA-256 hashes. See the IANA SSHFP RR parameters registry for details.
     */
    const val SSHFP = 44

    /**
     * IPsec Key record RFC 4025 Key record that can be used with IPsec.
     */
    const val IPSECKEY = 45

    /**
     * Resource Record Signature. DNSSEC signature record RFC 4034 Signature for a DNSSEC-secured record
     * set. Uses the same format as the SIG record.
     */
    const val RRSIG = 46

    /**
     * Next Secure Name. Next-Secure record RFC 4034 Part of DNSSEC, used to prove a name does not
     * exist. Uses the same format as the (obsolete) NXT record.
     */
    const val NSEC = 47

    /**
     * DNSSEC Key record RFC 4034 The key record used in DNSSEC. Uses the same
     * format as the KEY record.
     */
    const val DNSKEY = 48

    /**
     * Dynamic Host Configuration Protocol (DHCP) ID. DHCP identifier record RFC 4701
     * Used in conjunction with the FQDN option to DHCP.
     */
    const val DHCID = 49

    /**
     * Next SECure, 3rd edition, RFC 5155. An extension to DNSSEC that allows proof
     * of nonexistence for a name without permitting zonewalking.
     */
    const val NSEC3 = 50

    /**
     * NSEC3 parameters record RFC 5155 Parameter record for use with NSEC3.
     */
    const val NSEC3PARAM = 51

    /**
     * Transport Layer Security Authentication, draft-ietf-dane-protocol-23.
     * TLSA certificate association record RFC 6698 A record for DNS-based
     * Authentication of Named Entities (DANE). RFC 6698 defines The TLSA DNS
     * resource record is used to associate a TLS server certificate or public
     * key with the domain name where the record is found, thus forming a 'TLSA
     * certificate association'.
     */
    const val TLSA = 52

    /**
     * S/MIME cert association, draft-ietf-dane-smime
     */
    const val SMIMEA = 53

    /**
     * Host Identity Protocol record RFC 5205 Method of separating the end-point
     * identifier and locator roles of IP addresses.
     */
    const val HIP = 55

    /**
     * OpenPGP Key, RFC 7929
     */
    const val OPENPGPKEY = 61

    /**
     * Sender Policy Framework (experimental) record RFC 4408 Specified as part of the SPF
     * protocol as an alternative to of storing SPF data in TXT records. Uses
     * the same format as the earlier TXT record.
     */
    const val SPF = 99

    /**
     * Transaction key - used to compute a shared secret or exchange a key.
     * Secret key record RFC 2930 A method of providing keying material to be
     * used with TSIG that is encrypted under the public key in an accompanying
     * KEY RR..
     */
    const val TKEY = 249

    /**
     * Transaction Signature record RFC 2845 Can be used to authenticate dynamic
     * updates as coming from an approved client, or to authenticate responses
     * as coming from an approved recursive name server similar to DNSSEC.
     */
    const val TSIG = 250

    /**
     * Incremental Zone Transfer record RFC 1996 Requests a zone transfer of the
     * given zone but only differences from a previous serial number. This
     * request may be ignored and a full (AXFR) sent in response if the
     * authoritative server is unable to fulfill the request due to
     * configuration or lack of required deltas.
     */
    const val IXFR = 251

    /**
     * Authoritative Zone Transfer record RFC 1035 Transfer entire zone file
     * from the master name server to secondary name servers.
     */
    const val AXFR = 252

    /**
     * Transfer mailbox records
     */
    const val MAILB = 253

    /**
     * Transfer mail agent records
     */
    const val MAILA = 254

    /**
     * Matches any type
     *
     * All cached records RFC 1035 Returns all records of all types known to the
     * name server. If the name server does not have any information on the
     * name, the request will be forwarded on. The records returned may not be
     * complete. For example, if there is both an A and an MX for a name, but
     * the name server has only the A record cached, only the A record will be
     * returned. Sometimes referred to as ANY, for example in Windows nslookup
     * and Wireshark.
     */
    const val ANY = 255

    /**
     * URI
     *
     * @see [draft-faltstrom-uri-14](http://tools.ietf.org/html/draft-faltstrom-uri-14)
     */
    const val URI = 256

    /**
     * Certification Authority Authorization, RFC 6844. CA pinning,
     * constraining acceptable CAs for a host/domain.
     */
    const val CAA = 257

    /**
     * DNSSEC Trust Authorities record N/A Part of a deployment proposal for
     * DNSSEC without a signed DNS root. See the IANA database and Weiler Spec
     * for details. Uses the same format as the DS record.
     */
    const val TA = 32768

    /**
     * DNSSEC Lookaside Validation, RFC 4431. For publishing DNSSEC trust
     * anchors outside of the DNS delegation chain. Uses the same format as the
     * DS record. RFC 5074 describes a way of using these records.
     */
    const val DLV = 32769
    private val types = TypeMnemonic()

    init {
        // this is so we don't have to make each type constructor public
        DnsTypeProtoAssignment.assign(types)
    }

    /**
     * Checks that a numeric DnsRecordType is valid.
     *
     * @throws InvalidTypeException The type is out of range.
     */
    fun check(record: Int) {
        if (record < 0 || record > 0xFFFF) {
            throw InvalidTypeException(record)
        }
    }

    /**
     * Converts a numeric DnsRecordType into a String
     *
     * @param `val` The type value.
     *
     * @return The canonical string representation of the type
     *
     * @throws InvalidTypeException The type is out of range.
     */
    fun string(recordType: Int): String {
        return types.getText(recordType)
    }
    /**
     * Converts a String representation of an DnsRecordType into its numeric value.
     *
     * @param s The string representation of the type
     * @param numberok Whether a number will be accepted or not.
     *
     * @return The type code, or -1 on error.
     */
    /**
     * Converts a String representation of an DnsRecordType into its numeric value
     *
     * @return The type code, or -1 on error.
     */
    fun value(s: String, numberok: Boolean = false): Int {
        var `val` = types.getValue(s)
        if (`val` == -1 && numberok) {
            `val` = types.getValue("TYPE$s")
        }
        return `val`
    }

    fun <T : DnsRecord?> getProto(`val`: Int): T {
        return types.getProto(`val`)
    }

    /**
     * Is this type valid for a record (a non-meta type)?
     */
    fun isRR(type: Int): Boolean {
        return when (type) {
            OPT, TKEY, TSIG, IXFR, AXFR, MAILB, MAILA, ANY -> false
            else -> true
        }
    }

    private const val ptrSuffix = ".in-addr.arpa"

    /**
     * Guarantees that the specified host name is a FQND. This depends on it's type, which must also be specified.
     *
     * @param type the resource record type
     * @param hostName the hostname
     *
     * @return the Fully Qualified Domain Name for this hostname, depending on it's type
     */
    fun ensureFQDN(type: Int, hostName: String): String {
        // list of RecordTypes from: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/ResourceRecordTypes.html
        return when (type) {
            PTR -> {
                if (!hostName.endsWith(ptrSuffix)) {
                    // PTR absolutely MUST end in '.in-addr.arpa' in order for the DNS server to understand it.
                    // in this case, hostname is an ip address
                    return hostName + ptrSuffix
                }
                // resolving a hostname -> ip address, the hostname MUST end in a dot
                if (!hostName.endsWith('.')) {
                    "$hostName."
                } else {
                    hostName
                }
            }
            A, AAAA, CAA, CNAME, MX, NAPTR, NS, SOA, SPF, SRV, TXT -> if (!hostName.endsWith('.')) {
                "$hostName."
            } else {
                hostName
            }
            else -> hostName
        }
    }

    class TypeMnemonic : Mnemonic("DnsRecordType", CASE_UPPER) {
        private val objects: IntMap<DnsRecord>

        init {
            setPrefix("TYPE")
            objects = IntMap()
        }

        fun add(value: Int, str: String, proto: DnsRecord) {
            super.add(value, str)
            objects.put(value, proto)
        }

        @Suppress("UNCHECKED_CAST")
        fun <T : DnsRecord?> getProto(value: Int): T {
            check(value)
            return objects[value] as T
        }

        override fun check(`val`: Int) {
            DnsRecordType.check(`val`)
        }
    }
}
