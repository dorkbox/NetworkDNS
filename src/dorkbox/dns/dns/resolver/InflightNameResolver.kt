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

import io.netty.resolver.NameResolver
import io.netty.util.concurrent.EventExecutor
import io.netty.util.concurrent.Future
import io.netty.util.concurrent.FutureListener
import io.netty.util.concurrent.Promise
import io.netty.util.internal.StringUtil
import java.util.concurrent.*

// FIXME(trustin): Find a better name and move it to the 'resolver' module.
class InflightNameResolver<T> internal constructor(
    private val executor: EventExecutor,
    private val delegate: NameResolver<T>,
    private val resolvesInProgress: ConcurrentMap<String, Promise<T>>,
    private val resolveAllsInProgress: ConcurrentMap<String, Promise<List<T>>>
) : NameResolver<T> {

    override fun resolve(inetHost: String): Future<T> {
        return resolve(inetHost, executor.newPromise())
    }

    override fun resolve(inetHost: String, promise: Promise<T>): Promise<T> {
        return resolve(resolvesInProgress, inetHost, promise, false)
    }

    override fun resolveAll(inetHost: String): Future<List<T>> {
        return resolveAll(inetHost, executor.newPromise())
    }

    override fun resolveAll(inetHost: String, promise: Promise<List<T>>): Promise<List<T>> {
        return resolve(resolveAllsInProgress, inetHost, promise, true)
    }

    override fun close() {
        delegate.close()
    }

    private fun <U> resolve(
        resolveMap: ConcurrentMap<String, Promise<U>>, inetHost: String, promise: Promise<U>, resolveAll: Boolean
    ): Promise<U> {
        val earlyPromise = resolveMap.putIfAbsent(inetHost, promise)
        if (earlyPromise != null) {
            // Name resolution for the specified inetHost is in progress already.
            if (earlyPromise.isDone) {
                transferResult(earlyPromise, promise)
            } else {
                earlyPromise.addListener(FutureListener { f -> transferResult(f, promise) })
            }
        } else {
            try {
                if (resolveAll) {
                    val castPromise = promise as Promise<List<T>> // U is List<T>
                    delegate.resolveAll(inetHost, castPromise)
                } else {
                    val castPromise = promise as Promise<T> // U is T
                    delegate.resolve(inetHost, castPromise)
                }
            } finally {
                if (promise.isDone) {
                    resolveMap.remove(inetHost)
                } else {
                    promise.addListener(FutureListener { resolveMap.remove(inetHost) })
                }
            }
        }
        return promise
    }

    override fun toString(): String {
        return StringUtil.simpleClassName(this) + '(' + delegate + ')'
    }

    companion object {
        private fun <T> transferResult(src: Future<T>, dst: Promise<T>) {
            if (src.isSuccess) {
                dst.trySuccess(src.now)
            } else {
                dst.tryFailure(src.cause())
            }
        }
    }
}
