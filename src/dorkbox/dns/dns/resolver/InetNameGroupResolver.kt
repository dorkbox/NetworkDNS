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

import io.netty.resolver.AddressResolver
import io.netty.resolver.SimpleNameResolver
import io.netty.util.concurrent.EventExecutor
import java.net.InetAddress
import java.net.InetSocketAddress

abstract class InetNameGroupResolver
/**
 * @param executor the [EventExecutor] which is used to notify the listeners of the [Future] returned
 * by [.resolve]
 */
protected constructor(executor: EventExecutor) : SimpleNameResolver<List<InetAddress>>(executor) {

    @Volatile
    private var addressResolver: AddressResolver<InetSocketAddress>? = null

    /**
     * Return a [AddressResolver] that will use this name resolver underneath.
     * It's cached internally, so the same instance is always returned.
     */
    fun asAddressResolver(): AddressResolver<InetSocketAddress> {
        var result = addressResolver
        if (result == null) {
            synchronized(this) {
                result = addressResolver
                if (result == null) {
                    result = InetSocketAddressGroupResolver(executor(), this)
                    addressResolver = result
                }
            }
        }
        return result!!
    }
}
