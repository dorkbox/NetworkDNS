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

/**
 * The Name Server Identifier Option, define in RFC 5001.
 *
 * @author Brian Wellington
 * @see OPTRecord
 */
class NSIDOption : GenericEDNSOption {
    internal constructor() : super(Code.NSID) {}

    /**
     * Construct an NSID option.
     *
     * @param data The contents of the option.
     */
    constructor(data: ByteArray?) : super(Code.NSID, data) {}

    companion object {
        private const val serialVersionUID = 74739759292589056L
    }
}
