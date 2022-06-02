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
package dorkbox.dns.dns

import dorkbox.dns.dns.records.DnsMessage
import io.netty.buffer.ByteBuf
import io.netty.channel.AddressedEnvelope
import java.net.InetSocketAddress

/**
 *
 */
open class DnsEnvelope : DnsMessage, AddressedEnvelope<DnsEnvelope, InetSocketAddress?> {
    private var localAddress: InetSocketAddress? = null
    private var remoteAddress: InetSocketAddress? = null

    constructor() : super()
    constructor(id: Int, localAddress: InetSocketAddress?, remoteAddress: InetSocketAddress?) : super(id) {
        this.localAddress = localAddress
        this.remoteAddress = remoteAddress
    }

    constructor(buffer: ByteBuf?, localAddress: InetSocketAddress?, remoteAddress: InetSocketAddress?) : super(buffer!!) {
        this.localAddress = localAddress
        this.remoteAddress = remoteAddress
    }

    constructor(input: DnsInput?, localAddress: InetSocketAddress?, remoteAddress: InetSocketAddress?) : super(input!!) {
        this.localAddress = localAddress
        this.remoteAddress = remoteAddress
    }

    fun setLocalAddress(localAddress: InetSocketAddress?) {
        this.localAddress = localAddress
    }

    fun setRemoteAddress(remoteAddress: InetSocketAddress?) {
        this.remoteAddress = remoteAddress
    }

    override fun content(): DnsEnvelope {
        return this
    }

    override fun sender(): InetSocketAddress? {
        return localAddress
    }

    override fun recipient(): InetSocketAddress? {
        return remoteAddress
    }

    override fun touch(): DnsEnvelope {
        return super.touch() as DnsEnvelope
    }

    override fun touch(hint: Any): DnsEnvelope {
        return super.touch(hint) as DnsEnvelope
    }

    override fun retain(): DnsEnvelope {
        return super.retain() as DnsEnvelope
    }

    override fun retain(increment: Int): DnsEnvelope {
        return super.retain(increment) as DnsEnvelope
    }
}
