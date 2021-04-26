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

import java.io.IOException;

import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.utils.base16;

/**
 * An EDNSOption with no internal structure.
 *
 * @author Ming Zhou &lt;mizhou@bnivideo.com&gt;, Beaumaris Networks
 * @author Brian Wellington
 */
public
class GenericEDNSOption extends EDNSOption {

    private byte[] data;

    GenericEDNSOption(int code) {
        super(code);
    }

    /**
     * Construct a generic EDNS option.
     *
     * @param data The contents of the option.
     */
    public
    GenericEDNSOption(int code, byte[] data) {
        super(code);
        this.data = DnsRecord.checkByteArrayLength("option data", data, 0xFFFF);
    }

    @Override
    void optionFromWire(DnsInput in) throws IOException {
        data = in.readByteArray();
    }

    @Override
    void optionToWire(DnsOutput out) {
        out.writeByteArray(data);
    }

    @Override
    String optionToString() {
        return "<" + base16.toString(data) + ">";
    }

}
