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

import io.netty.resolver.AbstractAddressResolver
import io.netty.resolver.NameResolver
import io.netty.util.concurrent.EventExecutor
import io.netty.util.concurrent.Future
import io.netty.util.concurrent.FutureListener
import io.netty.util.concurrent.Promise
import java.net.InetAddress
import java.net.InetSocketAddress

class InetSocketAddressGroupResolver
/**
 * @param executor the [EventExecutor] which is used to notify the listeners of the [Future] returned
 * by [.resolve]
 * @param nameResolver the [NameResolver] used for name resolution
 */(executor: EventExecutor?, val nameResolver: NameResolver<List<InetAddress>>) :
    AbstractAddressResolver<InetSocketAddress>(executor, InetSocketAddress::class.java) {
    override fun doIsResolved(address: InetSocketAddress): Boolean {
        return !address.isUnresolved
    }

    @Throws(Exception::class)
    override fun doResolve(unresolvedAddress: InetSocketAddress, promise: Promise<InetSocketAddress>) {
        // Note that InetSocketAddress.getHostName() will never incur a reverse lookup here,
        // because an unresolved address always has a host name.
        nameResolver.resolve(unresolvedAddress.hostName).addListener(object : FutureListener<List<InetAddress>> {
                @Throws(Exception::class)
                override fun operationComplete(future: Future<List<InetAddress>>) {
                    if (future.isSuccess) {
                        val arrayList = ArrayList<InetSocketAddress>()
                        val now = future.now
                        for (inetAddress in now) {
                            arrayList.add(InetSocketAddress(inetAddress, unresolvedAddress.port))
                        }
                        // promise.setSuccess(arrayList);
                    } else {
                        promise.setFailure(future.cause())
                    }
                }
            })
    }

    @Throws(Exception::class)
    override fun doResolveAll(unresolvedAddress: InetSocketAddress, promise: Promise<List<InetSocketAddress>>) {
        // Note that InetSocketAddress.getHostName() will never incur a reverse lookup here,
        // because an unresolved address always has a host name.
        nameResolver.resolveAll(unresolvedAddress.hostName).addListener(object : FutureListener<List<List<InetAddress>>> {
                @Throws(Exception::class)
                override fun operationComplete(future: Future<List<List<InetAddress>>>) {
                    if (future.isSuccess) {
                        val inetAddresseses = future.now
                        val socketAddresses: MutableList<InetSocketAddress> = ArrayList(inetAddresseses.size)
                        for (inetAddresses in inetAddresseses) {
                            for (inetAddress in inetAddresses) {
                                socketAddresses.add(InetSocketAddress(inetAddress, unresolvedAddress.port))
                            }
                        }
                        promise.setSuccess(socketAddresses)
                    } else {
                        promise.setFailure(future.cause())
                    }
                }
            })
    }

    override fun close() {
        nameResolver.close()
    }
}
