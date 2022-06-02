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

import dorkbox.dns.dns.Compression
import dorkbox.dns.dns.DnsInput
import dorkbox.dns.dns.DnsOutput
import dorkbox.dns.dns.Name
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.utils.Options.check
import dorkbox.dns.dns.utils.Tokenizer
import dorkbox.os.OS.LINE_SEPARATOR
import java.io.IOException
import java.util.*

/**
 * OPENPGPKEY Record - Stores an OpenPGP certificate associated with a name.
 * RFC 7929.
 *
 * @author Brian Wellington
 * @author Valentin Hauner
 */
class OPENPGPKEYRecord : DnsRecord {
    /**
     * Returns the binary representation of the certificate
     */
    var cert: ByteArray? = null
        private set

    internal constructor() {}

    override val `object`: DnsRecord
        get() = OPENPGPKEYRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        cert = `in`.readByteArray()
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeByteArray(cert!!)
    }

    /**
     * Converts rdata to a String
     */
    override fun rrToString(sb: StringBuilder) {
        if (cert != null) {
            if (check("multiline")) {
                sb.append(LINE_SEPARATOR)
                sb.append(Base64.getEncoder().encodeToString(cert))
            } else {
                sb.append("\t")
                sb.append(Base64.getEncoder().encodeToString(cert))
            }
        }
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        cert = st.base64
    }

    /**
     * Creates an OPENPGPKEY Record from the given data
     *
     * @param cert Binary data representing the certificate
     */
    constructor(name: Name?, dclass: Int, ttl: Long, cert: ByteArray?) : super(name!!, DnsRecordType.OPENPGPKEY, dclass, ttl) {
        this.cert = cert
    }

    companion object {
        private const val serialVersionUID = -1277262990243423062L
    }
}
