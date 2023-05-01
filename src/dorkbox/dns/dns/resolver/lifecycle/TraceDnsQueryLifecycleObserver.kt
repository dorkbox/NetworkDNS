/*
 * Copyright 2023 dorkbox, llc
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
package dorkbox.dns.dns.resolver.lifecycle

import dorkbox.dns.dns.records.DnsMessage
import io.netty.channel.ChannelFuture
import io.netty.util.internal.ObjectUtil
import org.slf4j.Logger
import java.net.InetSocketAddress

internal class TraceDnsQueryLifecycleObserver(question: DnsMessage, logger: Logger) : DnsQueryLifecycleObserver {
    private val logger: Logger
    private val question: DnsMessage
    private var dnsServerAddress: InetSocketAddress? = null

    init {
        this.question = ObjectUtil.checkNotNull(question, "question")
        this.logger = ObjectUtil.checkNotNull(logger, "logger")
    }

    override fun queryWritten(dnsServerAddress: InetSocketAddress, future: ChannelFuture) {
        this.dnsServerAddress = dnsServerAddress
    }

    override fun queryCancelled(queriesRemaining: Int) {
        if (dnsServerAddress != null) {
            logger.trace("from {} : {} cancelled with {} queries remaining", dnsServerAddress, question, queriesRemaining)
        } else {
            logger.trace("{} query never written and cancelled with {} queries remaining", question, queriesRemaining)
        }
    }

    override fun queryRedirected(nameServers: List<InetSocketAddress>): DnsQueryLifecycleObserver {
        logger.trace("from {} : {} redirected", dnsServerAddress, question)
        return this
    }

    override fun queryCNAMEd(cnameQuestion: DnsMessage): DnsQueryLifecycleObserver {
        logger.trace("from {} : {} CNAME question {}", dnsServerAddress, question, cnameQuestion)
        return this
    }

    override fun queryNoAnswer(code: Int): DnsQueryLifecycleObserver {
        logger.trace("from {} : {} no answer {}", dnsServerAddress, question, code)
        return this
    }

    override fun queryFailed(cause: Throwable) {
        if (dnsServerAddress != null) {
            logger.trace("from {} : {} failure", dnsServerAddress, question, cause)
        } else {
            logger.trace("{} query never written and failed", question, cause)
        }
    }

    override fun querySucceed() {}
}
