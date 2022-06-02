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
package dorkbox.dns.dns.records

import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.constants.DnsRecordType.TypeMnemonic

object DnsTypeProtoAssignment {
    // this is so we don't have to make each type constructor public
    fun assign(types: TypeMnemonic) {
        types.add(DnsRecordType.A, "A", ARecord())
        types.add(DnsRecordType.NS, "NS", NSRecord())
        types.add(DnsRecordType.MD, "MD", MDRecord())
        types.add(DnsRecordType.MF, "MF", MFRecord())
        types.add(DnsRecordType.CNAME, "CNAME", CNAMERecord())
        types.add(DnsRecordType.SOA, "SOA", SOARecord())
        types.add(DnsRecordType.MB, "MB", MBRecord())
        types.add(DnsRecordType.MG, "MG", MGRecord())
        types.add(DnsRecordType.MR, "MR", MRRecord())
        types.add(DnsRecordType.NULL, "NULL", NULLRecord())
        types.add(DnsRecordType.WKS, "WKS", WKSRecord())
        types.add(DnsRecordType.PTR, "PTR", PTRRecord())
        types.add(DnsRecordType.HINFO, "HINFO", HINFORecord())
        types.add(DnsRecordType.MINFO, "MINFO", MINFORecord())
        types.add(DnsRecordType.MX, "MX", MXRecord())
        types.add(DnsRecordType.TXT, "TXT", TXTRecord())
        types.add(DnsRecordType.RP, "RP", RPRecord())
        types.add(DnsRecordType.AFSDB, "AFSDB", AFSDBRecord())
        types.add(DnsRecordType.X25, "X25", X25Record())
        types.add(DnsRecordType.ISDN, "ISDN", ISDNRecord())
        types.add(DnsRecordType.RT, "RT", RTRecord())
        types.add(DnsRecordType.NSAP, "NSAP", NSAPRecord())
        types.add(DnsRecordType.NSAP_PTR, "NSAP-PTR", NSAP_PTRRecord())
        types.add(DnsRecordType.SIG, "SIG", SIGRecord())
        types.add(DnsRecordType.KEY, "KEY", KEYRecord())
        types.add(DnsRecordType.PX, "PX", PXRecord())
        types.add(DnsRecordType.GPOS, "GPOS", GPOSRecord())
        types.add(DnsRecordType.AAAA, "AAAA", AAAARecord())
        types.add(DnsRecordType.LOC, "LOC", LOCRecord())
        types.add(DnsRecordType.NXT, "NXT", NXTRecord())
        types.add(DnsRecordType.EID, "EID")
        types.add(DnsRecordType.NIMLOC, "NIMLOC")
        types.add(DnsRecordType.SRV, "SRV", SRVRecord())
        types.add(DnsRecordType.ATMA, "ATMA")
        types.add(DnsRecordType.NAPTR, "NAPTR", NAPTRRecord())
        types.add(DnsRecordType.KX, "KX", KXRecord())
        types.add(DnsRecordType.CERT, "CERT", CERTRecord())
        types.add(DnsRecordType.A6, "A6", A6Record())
        types.add(DnsRecordType.DNAME, "DNAME", DNAMERecord())
        types.add(DnsRecordType.OPT, "OPT", OPTRecord())
        types.add(DnsRecordType.APL, "APL", APLRecord())
        types.add(DnsRecordType.DS, "DS", DSRecord())
        types.add(DnsRecordType.SSHFP, "SSHFP", SSHFPRecord())
        types.add(DnsRecordType.IPSECKEY, "IPSECKEY", IPSECKEYRecord())
        types.add(DnsRecordType.RRSIG, "RRSIG", RRSIGRecord())
        types.add(DnsRecordType.NSEC, "NSEC", NSECRecord())
        types.add(DnsRecordType.DNSKEY, "DNSKEY", DNSKEYRecord())
        types.add(DnsRecordType.DHCID, "DHCID", DHCIDRecord())
        types.add(DnsRecordType.NSEC3, "NSEC3", NSEC3Record())
        types.add(DnsRecordType.NSEC3PARAM, "NSEC3PARAM", NSEC3PARAMRecord())
        types.add(DnsRecordType.TLSA, "TLSA", TLSARecord())
        types.add(DnsRecordType.SMIMEA, "SMIMEA", SMIMEARecord())
        types.add(DnsRecordType.SMIMEA, "HIP")
        types.add(DnsRecordType.OPENPGPKEY, "OPENPGPKEY", OPENPGPKEYRecord())
        types.add(DnsRecordType.SPF, "SPF", SPFRecord())
        types.add(DnsRecordType.TKEY, "TKEY", TKEYRecord())
        types.add(DnsRecordType.TSIG, "TSIG", TSIGRecord())
        types.add(DnsRecordType.IXFR, "IXFR")
        types.add(DnsRecordType.AXFR, "AXFR")
        types.add(DnsRecordType.MAILB, "MAILB")
        types.add(DnsRecordType.MAILA, "MAILA")
        types.add(DnsRecordType.ANY, "ANY")
        types.add(DnsRecordType.URI, "URI", URIRecord())
        types.add(DnsRecordType.CAA, "CAA", CAARecord())
        types.add(DnsRecordType.TA, "TA")
        types.add(DnsRecordType.DLV, "DLV", DLVRecord())
    }
}
