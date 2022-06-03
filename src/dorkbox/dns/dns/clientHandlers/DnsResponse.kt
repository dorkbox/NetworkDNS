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
package dorkbox.dns.dns.clientHandlers

import dorkbox.dns.dns.DnsEnvelope
import dorkbox.dns.dns.DnsInput
import io.netty.channel.AddressedEnvelope
import io.netty.util.internal.UnstableApi
import java.net.InetSocketAddress
import java.net.SocketAddress

/**
 * A [DnsResponse] implementation for UDP/IP.
 */
@UnstableApi
class DnsResponse(dnsInput: DnsInput,
                  /**
                   * @param localAddress the address of the sender
                   */
                  localAddress: InetSocketAddress?,

                  /**
                   * @param remoteAddress the address of the recipient
                   */
                  remoteAddress: InetSocketAddress?) :
    DnsEnvelope(dnsInput, localAddress, remoteAddress) {

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
