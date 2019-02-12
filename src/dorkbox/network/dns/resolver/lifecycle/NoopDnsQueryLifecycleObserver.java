/*
 * Copyright 2018 dorkbox, llc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package dorkbox.network.dns.resolver.lifecycle;

import java.net.InetSocketAddress;
import java.util.List;

import dorkbox.network.dns.records.DnsMessage;
import io.netty.channel.ChannelFuture;

final
class NoopDnsQueryLifecycleObserver implements DnsQueryLifecycleObserver {
    static final NoopDnsQueryLifecycleObserver INSTANCE = new NoopDnsQueryLifecycleObserver();

    private
    NoopDnsQueryLifecycleObserver() {
    }

    @Override
    public
    void queryWritten(InetSocketAddress dnsServerAddress, ChannelFuture future) {
    }

    @Override
    public
    void queryCancelled(int queriesRemaining) {
    }

    @Override
    public
    DnsQueryLifecycleObserver queryRedirected(List<InetSocketAddress> nameServers) {
        return this;
    }

    @Override
    public
    DnsQueryLifecycleObserver queryCNAMEd(DnsMessage cnameQuestion) {
        return this;
    }

    @Override
    public
    DnsQueryLifecycleObserver queryNoAnswer(int code) {
        return this;
    }

    @Override
    public
    void queryFailed(Throwable cause) {
    }

    @Override
    public
    void querySucceed() {
    }
}
