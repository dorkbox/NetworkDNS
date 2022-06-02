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
package dorkbox.dns.dns.records

import dorkbox.dns.dns.DnsInput
import dorkbox.dns.dns.DnsOutput
import dorkbox.dns.dns.utils.base16.toString
import java.io.IOException

/**
 * An EDNSOption with no internal structure.
 *
 * @author Ming Zhou &lt;mizhou@bnivideo.com&gt;, Beaumaris Networks
 * @author Brian Wellington
 */
open class GenericEDNSOption : EDNSOption {
    override var data: ByteArray = byteArrayOf()

    internal constructor(code: Int) : super(code) {}

    /**
     * Construct a generic EDNS option.
     *
     * @param data The contents of the option.
     */
    constructor(code: Int, data: ByteArray?) : super(code) {
        this.data = DnsRecord.checkByteArrayLength("option data", data!!, 0xFFFF)
    }

    @Throws(IOException::class)
    override fun optionFromWire(`in`: DnsInput) {
        data = `in`.readByteArray()
    }

    override fun optionToWire(out: DnsOutput) {
        out.writeByteArray(data)
    }

    override fun optionToString(): String? {
        return "<" + toString(data) + ">"
    }
}
