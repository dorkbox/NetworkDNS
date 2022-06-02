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


import java.util.ArrayList;

import org.slf4j.Logger;

import dorkbox.dns.dns.records.ARecord;
import dorkbox.dns.dns.Name;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelPipeline;

/**
 *
 */
public
class DnsServerHandler extends ChannelInboundHandlerAdapter {
    protected final DnsMessageDecoder decoder;
    private final Logger logger;
    private DnsDecisionHandler decisionHandler;
    private DnsMessageEncoder encoder;

    public
    DnsServerHandler(final Logger logger) {
        this.logger = logger;

        decoder = new DnsMessageDecoder(logger);
        decisionHandler = new DnsDecisionHandler(logger);
        encoder = new DnsMessageEncoder(logger);
    }


    public
    void stop() {
        decisionHandler.stop();
    }


    /**
     * Adds a domain name query result, so clients that request the domain name will get the ipAddress
     *
     * @param domainName the domain name to have results for
     * @param @param aRecords the A records (can be multiple) to return for the requested domain name
     */
    public
    void addARecord(final Name domainName, final ArrayList<ARecord> aRecords) {
        decisionHandler.addARecord(domainName, aRecords);
    }

    @Override
    public final
    void channelRegistered(final ChannelHandlerContext context) {
        boolean success = false;
        try {
            initChannel(context.channel());
            context.fireChannelRegistered();
            success = true;
        } catch (Throwable t) {
            logger.error("Failed to initialize a channel. Closing: {}", context.channel(), t);
        } finally {
            if (!success) {
                context.close();
            }
        }
    }

    /**
     * STEP 1: Channel is first created
     */
    protected
    void initChannel(final Channel channel) {
        ChannelPipeline pipeline = channel.pipeline();

        ///////////////////////
        // DECODE (or upstream)
        ///////////////////////
        pipeline.addLast("decoder", decoder);
        pipeline.addLast("dnsDecision", decisionHandler);

        // ENCODE (or downstream)
        /////////////////////////
        pipeline.addLast("encoder", encoder);
        // pipeline.addLast("fowarder", new ForwardingHandler(logger));
        // pipeline.addLast("fowarder", new ForwardingHandler(this.config, this.clientChannelFactory));
    }
}
