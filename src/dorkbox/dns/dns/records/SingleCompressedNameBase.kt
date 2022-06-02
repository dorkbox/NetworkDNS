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

import dorkbox.dns.dns.Compression
import dorkbox.dns.dns.DnsOutput
import dorkbox.dns.dns.Name

/**
 * Implements common functionality for the many record types whose format is a single compressed name.
 *
 * @author Brian Wellington
 */
abstract class SingleCompressedNameBase : SingleNameBase {
    protected constructor()
    protected constructor(name: Name, type: Int, dclass: Int, ttl: Long, singleName: Name, description: String) : super(
        name, type, dclass, ttl, singleName, description)

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        singleName.toWire(out, c, canonical)
    }

    companion object {
        private const val serialVersionUID = -236435396815460677L
    }
}
