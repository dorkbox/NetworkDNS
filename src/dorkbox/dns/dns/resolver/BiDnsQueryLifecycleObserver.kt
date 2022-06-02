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

import dorkbox.dns.dns.records.DnsMessage
import io.netty.channel.ChannelFuture
import io.netty.util.internal.ObjectUtil
import io.netty.util.internal.UnstableApi
import java.net.InetSocketAddress

/**
 * Combines two [DnsQueryLifecycleObserver] into a single [DnsQueryLifecycleObserver].
 */
@UnstableApi
class BiDnsQueryLifecycleObserver(a: DnsQueryLifecycleObserver, b: DnsQueryLifecycleObserver) : DnsQueryLifecycleObserver {
    private val a: DnsQueryLifecycleObserver
    private val b: DnsQueryLifecycleObserver

    /**
     * Create a new instance.
     *
     * @param a The [DnsQueryLifecycleObserver] that will receive events first.
     * @param b The [DnsQueryLifecycleObserver] that will receive events second.
     */
    init {
        this.a = ObjectUtil.checkNotNull(a, "a")
        this.b = ObjectUtil.checkNotNull(b, "b")
    }

    override fun queryWritten(dnsServerAddress: InetSocketAddress, future: ChannelFuture) {
        try {
            a.queryWritten(dnsServerAddress, future)
        } finally {
            b.queryWritten(dnsServerAddress, future)
        }
    }

    override fun queryCancelled(queriesRemaining: Int) {
        try {
            a.queryCancelled(queriesRemaining)
        } finally {
            b.queryCancelled(queriesRemaining)
        }
    }

    override fun queryRedirected(nameServers: List<InetSocketAddress>): DnsQueryLifecycleObserver {
        try {
            a.queryRedirected(nameServers)
        } finally {
            b.queryRedirected(nameServers)
        }
        return this
    }

    override fun queryCNAMEd(cnameQuestion: DnsMessage): DnsQueryLifecycleObserver {
        try {
            a.queryCNAMEd(cnameQuestion)
        } finally {
            b.queryCNAMEd(cnameQuestion)
        }
        return this
    }

    override fun queryNoAnswer(code: Int): DnsQueryLifecycleObserver {
        try {
            a.queryNoAnswer(code)
        } finally {
            b.queryNoAnswer(code)
        }
        return this
    }

    override fun queryFailed(cause: Throwable) {
        try {
            a.queryFailed(cause)
        } finally {
            b.queryFailed(cause)
        }
    }

    override fun querySucceed() {
        try {
            a.querySucceed()
        } finally {
            b.querySucceed()
        }
    }
}
