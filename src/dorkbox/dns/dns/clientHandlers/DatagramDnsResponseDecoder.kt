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

import dorkbox.dns.dns.DnsInput
import dorkbox.dns.dns.exceptions.WireParseException
import dorkbox.dns.dns.records.Header
import io.netty.channel.ChannelHandler.Sharable
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.socket.DatagramPacket
import io.netty.handler.codec.MessageToMessageDecoder
import io.netty.util.internal.UnstableApi

/**
 * Decodes a [DatagramPacket] into a [DnsResponse].
 */
@UnstableApi
@Sharable
class DatagramDnsResponseDecoder
/**
 * Creates a new DNS Response decoder
 */
    : MessageToMessageDecoder<DatagramPacket>() {
    @Throws(Exception::class)
    override fun decode(ctx: ChannelHandlerContext, packet: DatagramPacket, out: MutableList<Any>) {
        val buf = packet.content()

        // Check that the response is long enough.
        if (buf.readableBytes() < Header.LENGTH) {
            throw WireParseException("invalid DNS header - " + "too short")
        }
        val dnsInput = DnsInput(buf)
        val dnsMessage = DnsResponse(dnsInput, packet.sender(), packet.recipient())
        out.add(dnsMessage)
    }
}
