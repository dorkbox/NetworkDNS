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
import dorkbox.dns.dns.utils.Tokenizer
import dorkbox.dns.dns.utils.base16.toString
import java.io.IOException

/**
 * SSH Fingerprint - stores the fingerprint of an SSH host key.
 *
 * @author Brian Wellington
 */
class SSHFPRecord : DnsRecord {
    /**
     * Returns the public key's algorithm.
     */
    var algorithm = 0
        private set

    /**
     * Returns the public key's digest type.
     */
    var digestType = 0
        private set

    /**
     * Returns the fingerprint
     */
    var fingerPrint: ByteArray? = null
        private set

    object Algorithm {
        const val RSA = 1
        const val DSS = 2
    }

    object Digest {
        const val SHA1 = 1
    }

    internal constructor() {}

    override val `object`: DnsRecord
        get() = SSHFPRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        algorithm = `in`.readU8()
        digestType = `in`.readU8()
        fingerPrint = `in`.readByteArray()
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeU8(algorithm)
        out.writeU8(digestType)
        out.writeByteArray(fingerPrint!!)
    }

    override fun rrToString(sb: StringBuilder) {
        sb.append(algorithm)
        sb.append(" ")
        sb.append(digestType)
        sb.append(" ")
        sb.append(toString(fingerPrint!!))
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        algorithm = st.getUInt8()
        digestType = st.getUInt8()
        fingerPrint = st.getHex(true)
    }

    /**
     * Creates an SSHFP Record from the given data.
     *
     * @param alg The public key's algorithm.
     * @param digestType The public key's digest type.
     * @param fingerprint The public key's fingerprint.
     */
    constructor(name: Name?, dclass: Int, ttl: Long, alg: Int, digestType: Int, fingerprint: ByteArray?) : super(
        name!!, DnsRecordType.SSHFP, dclass, ttl
    ) {
        algorithm = checkU8("alg", alg)
        this.digestType = checkU8("digestType", digestType)
        fingerPrint = fingerprint
    }

    companion object {
        private const val serialVersionUID = -8104701402654687025L
    }
}
