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
package dorkbox.dns.dns.resolver

import dorkbox.dns.dns.clientHandlers.DnsResponse
import io.netty.channel.Channel
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.util.concurrent.Promise

internal class DnsNameResolverResponseHandler(
    private val dnsNameResolver: DnsNameResolver,
    private val channelActivePromise: Promise<Channel>
) : ChannelInboundHandlerAdapter() {
    @Throws(Exception::class)
    override fun channelActive(ctx: ChannelHandlerContext) {
        super.channelActive(ctx)
        channelActivePromise.setSuccess(ctx.channel())
    }

    @Throws(Exception::class)
    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
        val response = msg as DnsResponse
        val queryId = response.header.iD
        if (DnsNameResolver.logger.isDebugEnabled) {
            DnsNameResolver.logger.debug("{} RECEIVED: [{}: {}], {}", dnsNameResolver.ch, queryId, response.sender(), response)
        }
        val qCtx = dnsNameResolver.queryContextManager[response.sender()!!, queryId]
        if (qCtx == null) {
            DnsNameResolver.logger.warn("{} Received a DNS response with an unknown ID: {}", dnsNameResolver.ch, queryId)
            return
        }
        qCtx.finish(response)
    }

    @Throws(Exception::class)
    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        DnsNameResolver.logger.warn("{} Unexpected exception: ", dnsNameResolver.ch, cause)
    }
}
