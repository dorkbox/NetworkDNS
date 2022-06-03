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
package dorkbox.dns.dns

import dorkbox.dns.dns.constants.DnsClass
import dorkbox.dns.dns.constants.DnsOpCode
import dorkbox.dns.dns.constants.DnsRecordType.ensureFQDN
import dorkbox.dns.dns.constants.DnsSection
import dorkbox.dns.dns.constants.Flags
import dorkbox.dns.dns.records.DnsRecord
import io.netty.channel.AddressedEnvelope
import java.net.IDN
import java.net.InetSocketAddress
import java.net.SocketAddress

/**
 *
 */
class DnsQuestion
/**
 * Creates a new instance.
 *
 * @param isResolveQuestion true if it's a resolve question, which means we ALSO are going to keep resolving names until we get an IP
 * address.
 */

private constructor(val isResolveQuestion: Boolean) : DnsEnvelope() {
    companion object {
        fun newResolveQuestion(inetHost: String, type: Int, isRecursionDesired: Boolean): DnsQuestion {
            return newQuestion(inetHost, type, isRecursionDesired, true)
        }

        fun newQuery(inetHost: String, type: Int, isRecursionDesired: Boolean): DnsQuestion {
            return newQuestion(inetHost, type, isRecursionDesired, false)
        }

        fun createName(hostName: String, type: Int): Name {
            // Convert to ASCII which will also check that the length is not too big. Throws null pointer if null.
            // See:
            //   - https://github.com/netty/netty/issues/4937
            //   - https://github.com/netty/netty/issues/4935
            // hostNameAsciiFix can throw a TextParseException if it fails to parse
            var hostName = hostNameAsciiFix(hostName)
            hostName = hostName.lowercase()

            // NOTE: have to make sure that the hostname is a FQDN name
            hostName = ensureFQDN(type, hostName)
            return try {
                Name.fromString(hostName)
            } catch (e: Exception) {
                // Name.fromString may throw a TextParseException if it fails to parse
                throw IllegalArgumentException("Hostname '$hostName' is invalid!")
            }
        }

        private fun newQuestion(inetHost: String, type: Int, isRecursionDesired: Boolean, isResolveQuestion: Boolean): DnsQuestion {
            val name = createName(inetHost, type)
            try {
                val questionRecord = DnsRecord.newRecord(name, type, DnsClass.IN)
                val question = DnsQuestion(isResolveQuestion)
                question.header.opcode = DnsOpCode.QUERY

                if (isRecursionDesired) {
                    question.header.setFlag(Flags.RD)
                }
                question.addRecord(questionRecord, DnsSection.QUESTION)

                // keep the question around so we can compare the response to it.
                question.retain()

                return question
            } catch (e: Exception) {
                throw IllegalArgumentException("Unable to create a question for $inetHost", e)
            }
        }

        fun hostNameAsciiFix(inetHost: String): String {
            try {
                val hostName = IDN.toASCII(inetHost) // can throw IllegalArgumentException

                // Check for http://bugs.java.com/bugdatabase/view_bug.do?bug_id=6894622

                return if (inetHost.endsWith('.') && !hostName.endsWith('.')) {
                    "$hostName."
                } else {
                    hostName
                }
            } catch (e: Exception) {
                // java.net.IDN.toASCII(...) may throw an IllegalArgumentException if it fails to parse the hostname
            }

            throw IllegalArgumentException("Hostname '$inetHost' is invalid!")
        }
    }

    fun init(id: Int, recipient: InetSocketAddress) {
        setRemoteAddress(id, recipient)
    }

    override fun hashCode(): Int {
        var hashCode = super.hashCode()
        if (sender() != null) {
            hashCode = hashCode * 31 + sender().hashCode()
        }
        if (recipient() != null) {
            hashCode = hashCode * 31 + recipient().hashCode()
        }
        return hashCode
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other == null) {
            return false
        }

        if (!super.equals(other)) {
            return false
        }
        if (other !is AddressedEnvelope<*, *>) {
            return false
        }

        val that = other as AddressedEnvelope<*, SocketAddress?>
        if (sender() == null) {
            if (that.sender() != null) {
                return false
            }
        } else if (sender() != that.sender()) {
            return false
        }

        if (recipient() == null) {
            if (that.recipient() != null) {
                return false
            }
        } else if (recipient() != that.recipient()) {
            return false
        }

        return true
    }
}
