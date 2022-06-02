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
import dorkbox.dns.dns.records.DnsMessage
import io.netty.util.internal.EmptyArrays
import io.netty.util.internal.ObjectUtil
import io.netty.util.internal.UnstableApi
import java.net.InetSocketAddress

/**
 * A [RuntimeException] raised when [DnsResolver] failed to perform a successful query.
 */
@UnstableApi
class DnsNameResolverException : RuntimeException {
    private val remoteAddress: InetSocketAddress
    private val question: DnsQuestion

    constructor(remoteAddress: InetSocketAddress, question: DnsQuestion, message: String?) : super(message) {
        this.remoteAddress = validateRemoteAddress(remoteAddress)
        this.question = validateQuestion(question)
    }

    constructor(remoteAddress: InetSocketAddress, question: DnsQuestion, message: String?, cause: Throwable?) : super(message, cause) {
        this.remoteAddress = validateRemoteAddress(remoteAddress)
        this.question = validateQuestion(question)
    }

    /**
     * Returns the [InetSocketAddress] of the DNS query that has failed.
     */
    fun remoteAddress(): InetSocketAddress {
        return remoteAddress
    }

    /**
     * Returns the [DnsQuestion] of the DNS query that has failed.
     */
    fun question(): DnsMessage {
        return question
    }

    override fun fillInStackTrace(): Throwable {
        stackTrace = EmptyArrays.EMPTY_STACK_TRACE
        return this
    }

    companion object {
        private const val serialVersionUID = -8826717909627131850L
        private fun validateRemoteAddress(remoteAddress: InetSocketAddress): InetSocketAddress {
            return ObjectUtil.checkNotNull(remoteAddress, "remoteAddress")
        }

        private fun validateQuestion(question: DnsQuestion): DnsQuestion {
            return ObjectUtil.checkNotNull(question, "question")
        }
    }
}
