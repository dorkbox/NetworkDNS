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
import java.net.InetSocketAddress

internal class NoopDnsQueryLifecycleObserver private constructor() : DnsQueryLifecycleObserver {
    companion object {
        val INSTANCE = NoopDnsQueryLifecycleObserver()
    }
    override fun queryWritten(dnsServerAddress: InetSocketAddress, future: ChannelFuture) {}
    override fun queryCancelled(queriesRemaining: Int) {}
    override fun queryRedirected(nameServers: List<InetSocketAddress>): DnsQueryLifecycleObserver {
        return this
    }

    override fun queryCNAMEd(cnameQuestion: DnsMessage): DnsQueryLifecycleObserver {
        return this
    }

    override fun queryNoAnswer(code: Int): DnsQueryLifecycleObserver {
        return this
    }

    override fun queryFailed(cause: Throwable) {}
    override fun querySucceed() {}


}
