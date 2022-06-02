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

package dorkbox.dns.dns.serverHandlers;

import java.io.IOException;

import org.slf4j.Logger;

import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.DnsServerResponse;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.socket.DatagramPacket;
import io.netty.handler.codec.MessageToByteEncoder;

/**
 *
 */
@ChannelHandler.Sharable
public
class DnsMessageEncoder extends MessageToByteEncoder<DnsServerResponse> {
    private final Logger logger;

    public
    DnsMessageEncoder(final Logger logger) {
        this.logger = logger;
    }

    @Override
    protected
    void encode(final ChannelHandlerContext context, final DnsServerResponse message, final ByteBuf out) throws Exception {
        try {
            DnsOutput dnsOutput = new DnsOutput(out);
            out.retain();
            message.toWire(dnsOutput);

            DatagramPacket packet = new DatagramPacket(out, message.recipient(), message.sender());
            context.channel()
                   .writeAndFlush(packet);
        } catch (Exception e) {
            context.fireExceptionCaught(new IOException("Unable to write dns message: " + message, e));
        }
    }

    @Override
    public
    void exceptionCaught(final ChannelHandlerContext context, final Throwable cause) throws Exception {
        logger.error("DnsMessageEncoder#exceptionCaught", cause);
        super.exceptionCaught(context, cause);
    }
}
