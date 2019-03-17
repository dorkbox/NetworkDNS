/*
 * Copyright 2015 The Netty Project
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

package dorkbox.network.dns.resolver.cache;

import static io.netty.util.internal.ObjectUtil.checkNotNull;

import java.net.InetAddress;
import java.util.concurrent.TimeUnit;

import io.netty.channel.EventLoop;
import io.netty.util.concurrent.ScheduledFuture;
import io.netty.util.internal.UnstableApi;

/**
 * Entry in {@link DnsCache}.
 */
@UnstableApi
public final class DnsCacheEntry {

    private final String hostname;
    private final InetAddress address;
    private final Throwable cause;
    private volatile ScheduledFuture<?> expirationFuture;

    public DnsCacheEntry(String hostname, InetAddress address) {
        this.hostname = checkNotNull(hostname, "hostname");
        this.address = checkNotNull(address, "address");
        cause = null;
    }

    public DnsCacheEntry(String hostname, Throwable cause) {
        this.hostname = checkNotNull(hostname, "hostname");
        this.cause = checkNotNull(cause, "cause");
        address = null;
    }

    public String hostname() {
        return hostname;
    }

    public InetAddress address() {
        return address;
    }

    public Throwable cause() {
        return cause;
    }

    void scheduleExpiration(EventLoop loop, Runnable task, long delay, TimeUnit unit) {
        assert expirationFuture == null: "expiration task scheduled already";
        expirationFuture = loop.schedule(task, delay, unit);
    }

    void cancelExpiration() {
        ScheduledFuture<?> expirationFuture = this.expirationFuture;
        if (expirationFuture != null) {
            expirationFuture.cancel(false);
        }
    }

    @Override
    public String toString() {
        if (cause != null) {
            return hostname + '/' + cause;
        } else {
            return address.toString();
        }
    }
}