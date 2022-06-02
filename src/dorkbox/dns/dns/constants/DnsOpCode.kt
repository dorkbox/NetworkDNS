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
 * Constants and functions relating to DNS opcodes
 *
 * @author Brian Wellington
 */
object DnsOpCode {
    /**
     * A standard query
     */
    const val QUERY = 0

    /**
     * An inverse query (deprecated)
     */
    const val IQUERY = 1

    /**
     * A server status request (not used)
     */
    const val STATUS = 2

    /**
     * A message from a primary to a secondary server to initiate a zone transfer
     */
    const val NOTIFY = 4

    /**
     * A dynamic update message
     */
    const val UPDATE = 5
    private val opcodes = Mnemonic("DNS DnsOpCode", Mnemonic.CASE_UPPER)

    init {
        opcodes.setMaximum(0xF)
        opcodes.setPrefix("RESERVED")
        opcodes.setNumericAllowed(true)
        opcodes.add(QUERY, "QUERY")
        opcodes.add(IQUERY, "IQUERY")
        opcodes.add(STATUS, "STATUS")
        opcodes.add(NOTIFY, "NOTIFY")
        opcodes.add(UPDATE, "UPDATE")
    }

    /**
     * Converts a numeric DnsOpCode into a String
     */
    fun string(i: Int): String {
        return opcodes.getText(i)
    }

    /**
     * Converts a String representation of an DnsOpCode into its numeric value
     */
    fun value(s: String): Int {
        return opcodes.getValue(s)
    }
}
