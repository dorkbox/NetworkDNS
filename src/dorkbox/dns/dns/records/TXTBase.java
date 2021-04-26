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
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.exceptions.TextParseException;
import dorkbox.dns.dns.utils.Tokenizer;
import dorkbox.dns.dns.Compression;
import dorkbox.dns.dns.DnsOutput;

/**
 * Implements common functionality for the many record types whose format
 * is a list of strings.
 *
 * @author Brian Wellington
 */

abstract
class TXTBase extends DnsRecord {

    private static final long serialVersionUID = -4319510507246305931L;

    protected List<byte[]> strings;

    protected
    TXTBase() {}

    protected
    TXTBase(Name name, int type, int dclass, long ttl) {
        super(name, type, dclass, ttl);
    }

    protected
    TXTBase(Name name, int type, int dclass, long ttl, String string) {
        this(name, type, dclass, ttl, Collections.singletonList(string));
    }

    protected
    TXTBase(Name name, int type, int dclass, long ttl, List<String> strings) {
        super(name, type, dclass, ttl);
        if (strings == null) {
            throw new IllegalArgumentException("strings must not be null");
        }
        this.strings = new ArrayList<byte[]>(strings.size());

        Iterator<String> it = strings.iterator();
        try {
            while (it.hasNext()) {
                String s = it.next();
                this.strings.add(byteArrayFromString(s));
            }
        } catch (TextParseException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
        strings = new ArrayList<byte[]>(2);

        while (in.remaining() > 0) {
            byte[] b = in.readCountedString();
            strings.add(b);
        }
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        for (final byte[] b : strings) {
            out.writeCountedString(b);
        }
    }

    /**
     * converts to a String
     */
    @Override
    void rrToString(StringBuilder sb) {
        Iterator<byte[]> it = strings.iterator();
        while (it.hasNext()) {
            byte[] array = it.next();
            sb.append(byteArrayToString(array, true));
            if (it.hasNext()) {
                sb.append(" ");
            }
        }
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        strings = new ArrayList<byte[]>(2);

        while (true) {
            Tokenizer.Token t = st.get();
            if (!t.isString()) {
                break;
            }
            try {
                strings.add(byteArrayFromString(t.value));
            } catch (TextParseException e) {
                throw st.exception(e.getMessage());
            }

        }
        st.unget();
    }

    /**
     * Returns the text strings
     *
     * @return A list of Strings corresponding to the text strings.
     */
    public
    List<String> getStrings() {
        List<String> list = new ArrayList<>(strings.size());

        for (int i = 0; i < strings.size(); i++) {
            list.add(byteArrayToString(strings.get(i), false));
        }
        return list;
    }

    /**
     * Returns the text strings
     *
     * @return A list of byte arrays corresponding to the text strings.
     */
    public
    List<byte[]> getStringsAsByteArrays() {
        return strings;
    }
}
