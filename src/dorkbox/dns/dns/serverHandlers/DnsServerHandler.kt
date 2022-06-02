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

import dorkbox.dns.dns.Name
import dorkbox.dns.dns.records.ARecord
import io.netty.channel.Channel
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import org.slf4j.Logger

/**
 *
 */
class DnsServerHandler(private val logger: Logger) : ChannelInboundHandlerAdapter() {
    protected val decoder: DnsMessageDecoder
    private val decisionHandler: DnsDecisionHandler
    private val encoder: DnsMessageEncoder

    init {
        decoder = DnsMessageDecoder(logger)
        decisionHandler = DnsDecisionHandler(logger)
        encoder = DnsMessageEncoder(logger)
    }

    fun stop() {
        decisionHandler.stop()
    }

    /**
     * Adds a domain name query result, so clients that request the domain name will get the ipAddress
     *
     * @param domainName the domain name to have results for
     * @param @param aRecords the A records (can be multiple) to return for the requested domain name
     */
    fun addARecord(domainName: Name, aRecords: List<ARecord>) {
        decisionHandler.addARecord(domainName, aRecords)
    }

    override fun channelRegistered(context: ChannelHandlerContext) {
        var success = false
        try {
            initChannel(context.channel())
            context.fireChannelRegistered()
            success = true
        } catch (t: Throwable) {
            logger.error("Failed to initialize a channel. Closing: {}", context.channel(), t)
        } finally {
            if (!success) {
                context.close()
            }
        }
    }

    /**
     * STEP 1: Channel is first created
     */
    protected fun initChannel(channel: Channel) {
        val pipeline = channel.pipeline()

        ///////////////////////
        // DECODE (or upstream)
        ///////////////////////
        pipeline.addLast("decoder", decoder)
        pipeline.addLast("dnsDecision", decisionHandler)

        // ENCODE (or downstream)
        /////////////////////////
        pipeline.addLast("encoder", encoder)
        // pipeline.addLast("fowarder", new ForwardingHandler(logger));
        // pipeline.addLast("fowarder", new ForwardingHandler(this.config, this.clientChannelFactory));
    }
}
