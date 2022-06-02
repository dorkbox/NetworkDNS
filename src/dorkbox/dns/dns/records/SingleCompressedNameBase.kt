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

package dorkbox.dns.dns.records;

import dorkbox.dns.dns.Compression;
import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.Name;

/**
 * Implements common functionality for the many record types whose format
 * is a single compressed name.
 *
 * @author Brian Wellington
 */

abstract
class SingleCompressedNameBase extends SingleNameBase {

    private static final long serialVersionUID = -236435396815460677L;

    protected
    SingleCompressedNameBase() {}

    protected
    SingleCompressedNameBase(Name name, int type, int dclass, long ttl, Name singleName, String description) {
        super(name, type, dclass, ttl, singleName, description);
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        singleName.toWire(out, c, canonical);
    }

}
