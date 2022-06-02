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

import dorkbox.dns.dns.DnsQuestion
import dorkbox.dns.dns.clientHandlers.DnsResponse
import dorkbox.dns.dns.constants.DnsSection
import io.netty.channel.ChannelFuture
import io.netty.channel.ChannelFutureListener
import io.netty.channel.ChannelPromise
import io.netty.util.concurrent.Promise
import io.netty.util.concurrent.ScheduledFuture
import io.netty.util.internal.ObjectUtil
import org.slf4j.LoggerFactory
import java.net.InetSocketAddress
import java.util.concurrent.*

internal class DnsQueryContext(parent: DnsNameResolver, nameServerAddr: InetSocketAddress, question: DnsQuestion, promise: Promise<DnsResponse>) {
    private val parent: DnsNameResolver
    private val promise: Promise<DnsResponse>
    private val id: Int
    private val question: DnsQuestion
    private val nameServerAddr: InetSocketAddress

    @Volatile
    private var timeoutFuture: ScheduledFuture<*>? = null

    init {
        this.parent = ObjectUtil.checkNotNull(parent, "parent")
        this.nameServerAddr = ObjectUtil.checkNotNull(nameServerAddr, "nameServerAddr")
        this.question = ObjectUtil.checkNotNull(question, "question")
        this.promise = ObjectUtil.checkNotNull(promise, "promise")
        id = parent.queryContextManager.add(this)
        question.init(id, nameServerAddr)
    }

    fun query(writePromise: ChannelPromise) {
        val question = question()
        val nameServerAddr = nameServerAddr()
        if (logger.isDebugEnabled) {
            logger.debug("{} WRITE: [{}: {}], {}", parent.ch, id, nameServerAddr, question)
        }
        sendQuery(question, writePromise)
    }

    fun nameServerAddr(): InetSocketAddress {
        return nameServerAddr
    }

    fun question(): DnsQuestion {
        return question
    }

    private fun sendQuery(query: DnsQuestion, writePromise: ChannelPromise) {
        if (parent.channelFuture.isDone) {
            writeQuery(query, writePromise)
        } else {
            parent.channelFuture.addListener { future ->
                if (future.isSuccess) {
                    writeQuery(query, writePromise)
                } else {
                    val cause = future.cause()
                    promise.tryFailure(cause)
                    writePromise.setFailure(cause)
                }
            }
        }
    }

    private fun writeQuery(query: DnsQuestion, writePromise: ChannelPromise) {
        val writeFuture = parent.ch.writeAndFlush(query, writePromise)
        if (writeFuture.isDone) {
            onQueryWriteCompletion(writeFuture)
        } else {
            writeFuture.addListener(ChannelFutureListener { onQueryWriteCompletion(writeFuture) })
        }
    }

    private fun onQueryWriteCompletion(writeFuture: ChannelFuture) {
        if (!writeFuture.isSuccess) {
            writeFuture.cause().printStackTrace()
            setFailure("failed to send a query", writeFuture.cause())
            return
        }

        // Schedule a query timeout task if necessary.
        val queryTimeoutMillis = parent.queryTimeoutMillis()
        if (queryTimeoutMillis > 0) {
            timeoutFuture = parent.ch.eventLoop().schedule(Runnable {
                    if (promise.isDone) {
                        // Received a response before the query times out.
                        return@Runnable
                    }
                    setFailure("query timed out after $queryTimeoutMillis milliseconds", null)
                }, queryTimeoutMillis, TimeUnit.MILLISECONDS)
        }
    }

    private fun setFailure(message: String, cause: Throwable?) {
        val nameServerAddr = nameServerAddr()
        parent.queryContextManager.remove(nameServerAddr, id)
        val buf = StringBuilder(message.length + 64)
        buf.append('[').append(nameServerAddr).append("] ").append(message).append(" (no stack trace available)")
        val e: DnsNameResolverException
        e = if (cause != null) {
            DnsNameResolverException(nameServerAddr, question(), buf.toString(), cause)
        } else {
            DnsNameResolverException(nameServerAddr, question(), buf.toString())
        }
        promise.tryFailure(e)
    }

    fun finish(response: DnsResponse) {
        try {
            val sectionArray = response.getSectionArray(DnsSection.QUESTION)
            if (sectionArray.size != 1) {
                logger.warn("Received a DNS response with invalid number of questions: {}", response)
                return
            }
            val questionArray = question.getSectionArray(DnsSection.QUESTION)
            if (questionArray.size != 1) {
                logger.warn("Received a DNS response with invalid number of query questions: {}", response)
                return
            }
            if (!questionArray[0].equals(sectionArray[0])) {
                logger.warn("Received a mismatching DNS response: {}", response)
                return
            }
            setSuccess(response)
        } finally {
            if (question.isResolveQuestion) {
                // for resolve questions (always A/AAAA), we convert the answer into InetAddress, however with OTHER TYPES, we pass
                // back the result to the user, and if we release it, all of the content will be cleared.
                response.release()
            }
        }
    }

    private fun setSuccess(response: DnsResponse) {
        parent.queryContextManager.remove(nameServerAddr(), id)

        // Cancel the timeout task.
        val timeoutFuture = timeoutFuture
        timeoutFuture?.cancel(false)
        val promise = promise
        if (promise.setUncancellable()) {
            response.retain()
            // response now has a refCnt = 2
            if (!promise.trySuccess(response)) { // question is used here!
                // We failed to notify the promise as it was failed before, thus we need to release the envelope
                response.release()
            }
            response.release()
        }
    }

    companion object {
        private val logger = LoggerFactory.getLogger(DnsQueryContext::class.java)
    }
}
