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

import dorkbox.dns.dns.Mnemonic

/**
 * Constants and functions relating to DNS rcodes (error values)
 *
 * @author Brian Wellington
 */
object DnsResponseCode {
    private val rcodes = Mnemonic("DNS DnsResponseCode", Mnemonic.CASE_UPPER)
    private val tsigrcodes = Mnemonic("TSIG rcode", Mnemonic.CASE_UPPER)

    /**
     * No error
     */
    const val NOERROR = 0

    /**
     * Format error
     */
    const val FORMERR = 1

    /**
     * Server failure
     */
    const val SERVFAIL = 2

    /**
     * The name does not exist
     */
    const val NXDOMAIN = 3

    /**
     * The operation requested is not implemented
     */
    const val NOTIMP = 4

    /**
     * Deprecated synonym for NOTIMP.
     */
    const val NOTIMPL = 4

    /**
     * The operation was refused by the server
     */
    const val REFUSED = 5

    /**
     * The name exists
     */
    const val YXDOMAIN = 6

    /**
     * The RRset (name, type) exists
     */
    const val YXRRSET = 7

    /**
     * The RRset (name, type) does not exist
     */
    const val NXRRSET = 8

    /**
     * The requestor is not authorized to perform this operation
     */
    const val NOTAUTH = 9

    /**
     * The zone specified is not a zone
     */
    const val NOTZONE = 10
    /* EDNS extended rcodes */
    /**
     * Unsupported EDNS level
     */
    const val BADVERS = 16
    /* TSIG/TKEY only rcodes */
    /**
     * The signature is invalid (TSIG/TKEY extended error)
     */
    const val BADSIG = 16

    /**
     * The key is invalid (TSIG/TKEY extended error)
     */
    const val BADKEY = 17

    /**
     * The time is out of range (TSIG/TKEY extended error)
     */
    const val BADTIME = 18

    /**
     * The mode is invalid (TKEY extended error)
     */
    const val BADMODE = 19

    /**
     * The 'BADNAME' DNS RCODE (20), as defined in [RFC2930](https://tools.ietf.org/html/rfc2930).
     */
    const val BADNAME = 20

    /**
     * The 'BADALG' DNS RCODE (21), as defined in [RFC2930](https://tools.ietf.org/html/rfc2930).
     */
    const val BADALG = 21

    init {
        rcodes.setMaximum(0xFFF)
        rcodes.setPrefix("RESERVED")
        rcodes.setNumericAllowed(true)
        rcodes.add(NOERROR, "NOERROR")
        rcodes.add(FORMERR, "FORMERR")
        rcodes.add(SERVFAIL, "SERVFAIL")
        rcodes.add(NXDOMAIN, "NXDOMAIN")
        rcodes.add(NOTIMP, "NOTIMP")
        rcodes.addAlias(NOTIMP, "NOTIMPL")
        rcodes.add(REFUSED, "REFUSED")
        rcodes.add(YXDOMAIN, "YXDOMAIN")
        rcodes.add(YXRRSET, "YXRRSET")
        rcodes.add(NXRRSET, "NXRRSET")
        rcodes.add(NOTAUTH, "NOTAUTH")
        rcodes.add(NOTZONE, "NOTZONE")
        rcodes.add(BADVERS, "BADVERS")
        tsigrcodes.setMaximum(0xFFFF)
        tsigrcodes.setPrefix("RESERVED")
        tsigrcodes.setNumericAllowed(true)
        tsigrcodes.addAll(rcodes)
        tsigrcodes.add(BADSIG, "BADSIG")
        tsigrcodes.add(BADKEY, "BADKEY")
        tsigrcodes.add(BADTIME, "BADTIME")
        tsigrcodes.add(BADMODE, "BADMODE")
        tsigrcodes.add(BADNAME, "BADNAME")
        tsigrcodes.add(BADALG, "BADALG")
    }

    /**
     * Converts a numeric DnsResponseCode into a String
     */
    fun string(i: Int): String {
        return rcodes.getText(i)
    }

    /**
     * Converts a numeric TSIG extended DnsResponseCode into a String
     */
    fun TSIGstring(i: Int): String {
        return tsigrcodes.getText(i)
    }

    /**
     * Converts a String representation of an DnsResponseCode into its numeric value
     */
    fun value(s: String): Int {
        return rcodes.getValue(s)
    }
}
