/*
 * Copyright 2017 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package dorkbox.network.dns.resolver;

import static io.netty.util.internal.ObjectUtil.checkNotNull;

import java.net.InetSocketAddress;
import java.util.List;

import org.slf4j.Logger;

import dorkbox.network.dns.records.DnsMessage;
import io.netty.channel.ChannelFuture;

final
class TraceDnsQueryLifecycleObserver implements DnsQueryLifecycleObserver {
    private final Logger logger;
    private final DnsMessage question;
    private InetSocketAddress dnsServerAddress;

    TraceDnsQueryLifecycleObserver(DnsMessage question, Logger logger) {
        this.question = checkNotNull(question, "question");
        this.logger = checkNotNull(logger, "logger");
    }

    @Override
    public
    void queryWritten(InetSocketAddress dnsServerAddress, ChannelFuture future) {
        this.dnsServerAddress = dnsServerAddress;
    }

    @Override
    public
    void queryCancelled(int queriesRemaining) {
        if (dnsServerAddress != null) {
            logger.trace("from {} : {} cancelled with {} queries remaining", dnsServerAddress, question, queriesRemaining);
        }
        else {
            logger.trace("{} query never written and cancelled with {} queries remaining", question, queriesRemaining);
        }
    }

    @Override
    public
    DnsQueryLifecycleObserver queryRedirected(List<InetSocketAddress> nameServers) {
        logger.trace("from {} : {} redirected", dnsServerAddress, question);
        return this;
    }

    @Override
    public
    DnsQueryLifecycleObserver queryCNAMEd(DnsMessage cnameQuestion) {
        logger.trace("from {} : {} CNAME question {}", dnsServerAddress, question, cnameQuestion);
        return this;
    }

    @Override
    public
    DnsQueryLifecycleObserver queryNoAnswer(int code) {
        logger.trace("from {} : {} no answer {}", dnsServerAddress, question, code);
        return this;
    }

    @Override
    public
    void queryFailed(Throwable cause) {
        if (dnsServerAddress != null) {
            logger.trace("from {} : {} failure", dnsServerAddress, question, cause);
        }
        else {
            logger.trace("{} query never written and failed", question, cause);
        }
    }

    @Override
    public
    void querySucceed() {
    }
}
