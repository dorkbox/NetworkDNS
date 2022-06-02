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

import java.net.InetSocketAddress;
import java.util.List;

import org.slf4j.Logger;

import dorkbox.dns.dns.records.Header;
import dorkbox.dns.dns.DnsEnvelope;
import dorkbox.dns.dns.exceptions.WireParseException;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.socket.DatagramPacket;
import io.netty.handler.codec.MessageToMessageDecoder;

class DnsMessageDecoder extends MessageToMessageDecoder<DatagramPacket> {
    private final Logger logger;

    DnsMessageDecoder(final Logger logger) {
        this.logger = logger;
    }

    @Override
    public
    void exceptionCaught(final ChannelHandlerContext context, final Throwable cause) throws Exception {
        logger.error("DnsMessageDecoder#exceptionCaught", cause);
        super.exceptionCaught(context, cause);
    }

    @Override
    protected
    void decode(ChannelHandlerContext context, DatagramPacket packet, List<Object> out) throws Exception {
        final ByteBuf buf = packet.content();

        // Check that the response is long enough.
        if (buf.readableBytes() < Header.LENGTH) {
            throw new WireParseException("invalid DNS header - " + "too short");
        }

        boolean success = false;
        try {
            InetSocketAddress localAddress = packet.recipient();
            InetSocketAddress remoteAddress = packet.sender();

            DnsEnvelope dnsEnvelope = new DnsEnvelope(buf, localAddress, remoteAddress);
            out.add(dnsEnvelope);
            success = true;
        } finally {
            if (!success) {
                buf.release();
            }
        }
    }
}
