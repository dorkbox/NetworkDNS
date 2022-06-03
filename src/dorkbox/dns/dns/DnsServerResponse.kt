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

import dorkbox.dns.dns.records.DnsMessage
import io.netty.channel.AddressedEnvelope
import io.netty.util.internal.UnstableApi
import java.net.InetSocketAddress
import java.net.SocketAddress

/**
 * A [DnsServerResponse] implementation for UDP/IP.
 */
@UnstableApi
class DnsServerResponse(dnsQuestion: DnsMessage, localAddress: InetSocketAddress, remoteAddress: InetSocketAddress)
    : DnsEnvelope(dnsQuestion.header.id, localAddress, remoteAddress) {

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

    override fun equals(obj: Any?): Boolean {
        if (this === obj) {
            return true
        }
        if (!super.equals(obj)) {
            return false
        }
        if (obj !is AddressedEnvelope<*, *>) {
            return false
        }
        val that = obj as AddressedEnvelope<*, SocketAddress?>
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
