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
package dorkbox.dns.dns.serverHandlers

import dorkbox.dns.dns.DnsEnvelope
import dorkbox.dns.dns.exceptions.WireParseException
import dorkbox.dns.dns.records.Header
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.socket.DatagramPacket
import io.netty.handler.codec.MessageToMessageDecoder
import org.slf4j.Logger

class DnsMessageDecoder(private val logger: Logger) : MessageToMessageDecoder<DatagramPacket>() {
    @Throws(Exception::class)
    override fun exceptionCaught(context: ChannelHandlerContext, cause: Throwable) {
        logger.error("DnsMessageDecoder#exceptionCaught", cause)
        super.exceptionCaught(context, cause)
    }

    @Throws(Exception::class)
    override fun decode(context: ChannelHandlerContext, packet: DatagramPacket, out: MutableList<Any>) {
        val buf = packet.content()

        // Check that the response is long enough.
        if (buf.readableBytes() < Header.LENGTH) {
            throw WireParseException("invalid DNS header - " + "too short")
        }
        var success = false
        success = try {
            val localAddress = packet.recipient()
            val remoteAddress = packet.sender()
            val dnsEnvelope = DnsEnvelope(buf, localAddress, remoteAddress)
            out.add(dnsEnvelope)
            true
        } finally {
            if (!success) {
                buf.release()
            }
        }
    }
}
