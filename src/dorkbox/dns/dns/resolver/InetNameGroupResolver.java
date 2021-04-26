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

package dorkbox.dns.dns.resolver;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;

import io.netty.resolver.AddressResolver;
import io.netty.resolver.SimpleNameResolver;
import io.netty.util.concurrent.EventExecutor;

public abstract class InetNameGroupResolver extends SimpleNameResolver<List<InetAddress>> {
    private volatile AddressResolver<InetSocketAddress> addressResolver;

    /**
     * @param executor the {@link EventExecutor} which is used to notify the listeners of the {@link Future} returned
     *                 by {@link #resolve(String)}
     */
    protected
    InetNameGroupResolver(EventExecutor executor) {
        super(executor);
    }

    /**
     * Return a {@link AddressResolver} that will use this name resolver underneath.
     * It's cached internally, so the same instance is always returned.
     */
    public AddressResolver<InetSocketAddress> asAddressResolver() {
        AddressResolver<InetSocketAddress> result = addressResolver;
        if (result == null) {
            synchronized (this) {
                result = addressResolver;
                if (result == null) {
                    addressResolver = result = new InetSocketAddressGroupResolver(executor(), this);
                }
            }
        }
        return result;
    }
}
