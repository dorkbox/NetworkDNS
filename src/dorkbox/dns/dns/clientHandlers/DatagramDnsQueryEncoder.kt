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

import dorkbox.dns.dns.DnsOutput
import dorkbox.dns.dns.DnsQuestion
import dorkbox.dns.dns.records.DnsMessage
import dorkbox.util.logger
import io.netty.channel.AddressedEnvelope
import io.netty.channel.ChannelHandler.Sharable
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.socket.DatagramPacket
import io.netty.handler.codec.MessageToMessageEncoder
import io.netty.util.internal.UnstableApi
import java.net.InetSocketAddress

/**
 * Encodes an [AddressedEnvelope] of [DnsQuestion]} into a [DatagramPacket].
 */
@UnstableApi
@Sharable
class DatagramDnsQueryEncoder(private val maxPayloadSize: Int) : MessageToMessageEncoder<AddressedEnvelope<DnsQuestion, InetSocketAddress?>>() {
    override fun encode(ctx: ChannelHandlerContext, `in`: AddressedEnvelope<DnsQuestion, InetSocketAddress?>, out: MutableList<Any>) {
        val recipient = `in`.recipient()
        val query: DnsMessage = `in`.content()
        val buf = ctx.alloc().ioBuffer(maxPayloadSize)

        var success = false
        try {
            val dnsOutput = DnsOutput(buf)
            query.toWire(dnsOutput)
            out.add(DatagramPacket(buf, recipient, null))
            success = true
        } catch (e: Exception) {
            logger().error(e) { "UNABLE TO ENCODE MESSAGE?" }
        } finally {
            if (!success) {
                buf.release()
            }
        }
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        cause.printStackTrace()
    }
}
