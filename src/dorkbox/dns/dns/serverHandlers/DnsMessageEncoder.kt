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

import dorkbox.dns.dns.DnsOutput
import dorkbox.dns.dns.DnsServerResponse
import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelHandler.Sharable
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.socket.DatagramPacket
import io.netty.handler.codec.MessageToByteEncoder
import org.slf4j.Logger
import java.io.IOException

/**
 *
 */
@Sharable
class DnsMessageEncoder(private val logger: Logger) : MessageToByteEncoder<DnsServerResponse>() {
    @Throws(Exception::class)
    override fun encode(context: ChannelHandlerContext, message: DnsServerResponse, out: ByteBuf) {
        try {
            val dnsOutput = DnsOutput(out)
            out.retain()
            message.toWire(dnsOutput)
            val packet = DatagramPacket(out, message.recipient(), message.sender())
            context.channel().writeAndFlush(packet)
        } catch (e: Exception) {
            context.fireExceptionCaught(IOException("Unable to write dns message: $message", e))
        }
    }

    @Throws(Exception::class)
    override fun exceptionCaught(context: ChannelHandlerContext, cause: Throwable) {
        logger.error("DnsMessageEncoder#exceptionCaught", cause)
        super.exceptionCaught(context, cause)
    }
}
