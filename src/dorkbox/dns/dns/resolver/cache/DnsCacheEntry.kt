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
package dorkbox.dns.dns.resolver.cache

import io.netty.channel.EventLoop
import io.netty.util.concurrent.ScheduledFuture
import io.netty.util.internal.ObjectUtil
import io.netty.util.internal.UnstableApi
import java.net.InetAddress
import java.util.concurrent.*

/**
 * Entry in [DnsCache].
 */
@UnstableApi
class DnsCacheEntry {
    private val hostname: String
    private val address: InetAddress?
    private val cause: Throwable?

    @Volatile
    private var expirationFuture: ScheduledFuture<*>? = null

    constructor(hostname: String, address: InetAddress) {
        this.hostname = ObjectUtil.checkNotNull(hostname, "hostname")
        this.address = ObjectUtil.checkNotNull(address, "address")
        cause = null
    }

    constructor(hostname: String, cause: Throwable) {
        this.hostname = ObjectUtil.checkNotNull(hostname, "hostname")
        this.cause = ObjectUtil.checkNotNull(cause, "cause")
        address = null
    }

    fun hostname(): String {
        return hostname
    }

    fun address(): InetAddress? {
        return address
    }

    fun cause(): Throwable? {
        return cause
    }

    fun scheduleExpiration(loop: EventLoop, task: Runnable?, delay: Long, unit: TimeUnit?) {
        assert(expirationFuture == null) { "expiration task scheduled already" }
        expirationFuture = loop.schedule(task, delay, unit)
    }

    fun cancelExpiration() {
        val expirationFuture = expirationFuture
        expirationFuture?.cancel(false)
    }

    override fun toString(): String {
        return if (cause != null) {
            "$hostname/$cause"
        } else {
            address.toString()
        }
    }
}
