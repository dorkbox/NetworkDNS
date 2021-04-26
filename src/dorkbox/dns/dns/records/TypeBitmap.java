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

/**
 * Routines for deal with the lists of types found in NSEC/NSEC3 records.
 *
 * @author Brian Wellington
 */

import java.io.IOException;
import java.io.Serializable;
import java.util.Iterator;
import java.util.TreeSet;

import dorkbox.dns.dns.utils.Tokenizer;
import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.constants.DnsRecordType;
import dorkbox.dns.dns.exceptions.WireParseException;
import dorkbox.util.collections.IntMap;
import dorkbox.util.collections.IntMap.Keys;

final
class TypeBitmap implements Serializable {

    private static final long serialVersionUID = -125354057735389003L;

    private IntMap<Boolean> types;

    public
    TypeBitmap(int[] array) {
        this();
        for (int i = 0; i < array.length; i++) {
            DnsRecordType.check(array[i]);
            types.put(array[i], Boolean.TRUE);
        }
    }

    private
    TypeBitmap() {
        types = new IntMap<Boolean>();
    }

    public
    TypeBitmap(DnsInput in) throws WireParseException {
        this();
        int lastbase = -1;

        while (in.remaining() > 0) {
            if (in.remaining() < 2) {
                throw new WireParseException("invalid bitmap descriptor");
            }

            int mapbase = in.readU8();
            if (mapbase < lastbase) {
                throw new WireParseException("invalid ordering");
            }

            int maplength = in.readU8();
            if (maplength > in.remaining()) {
                throw new WireParseException("invalid bitmap");
            }

            for (int i = 0; i < maplength; i++) {
                int current = in.readU8();
                if (current == 0) {
                    continue;
                }

                for (int j = 0; j < 8; j++) {
                    if ((current & (1 << (7 - j))) == 0) {
                        continue;
                    }

                    int typecode = mapbase * 256 + +i * 8 + j;
                    types.put(typecode, Boolean.TRUE);
                }
            }
        }
    }

    public
    TypeBitmap(Tokenizer st) throws IOException {
        this();

        while (true) {
            Tokenizer.Token t = st.get();
            if (!t.isString()) {
                break;
            }

            int typecode = DnsRecordType.value(t.value);
            if (typecode < 0) {
                throw st.exception("Invalid type: " + t.value);
            }

            types.put(typecode, Boolean.TRUE);
        }
        st.unget();
    }

    public
    int[] toArray() {
        int[] array = new int[types.size];
        int n = 0;


        Keys keys = types.keys();
        while (keys.hasNext) {
            array[n++] = keys.next();
        }

        return array;
    }

    @Override
    public
    String toString() {
        StringBuilder sb = new StringBuilder();

        Keys keys = types.keys();
        while (keys.hasNext) {
            int t = keys.next();
            sb.append(DnsRecordType.string(t))
              .append(' ');
        }

        // remove the last ' '
        int length = sb.length();
        if (length > 1) {
            sb.delete(length - 1, length);
        }

        return sb.toString();
    }

    public
    void toWire(DnsOutput out) {
        if (types.size == 0) {
            return;
        }

        int mapbase = -1;
        TreeSet<Integer> map = new TreeSet<>();

        Keys keys = types.keys();
        while (keys.hasNext) {
            int t = keys.next();

            int base = t >> 8;
            if (base != mapbase) {
                if (map.size() > 0) {
                    mapToWire(out, map, mapbase);
                    map.clear();
                }
                mapbase = base;
            }
            map.add(t);
        }

        mapToWire(out, map, mapbase);
    }

    /**
     * @param map this must be an ordered data structure!
     */
    private static
    void mapToWire(DnsOutput out, TreeSet<Integer> map, int mapbase) {
        int arraymax = map.last() & 0xFF;
        int arraylength = (arraymax / 8) + 1;
        int[] array = new int[arraylength];

        out.writeU8(mapbase);
        out.writeU8(arraylength);

        for (Iterator<Integer> it = map.iterator(); it.hasNext(); ) {
            int typecode = it.next();
            array[(typecode & 0xFF) / 8] |= (1 << (7 - typecode % 8));
        }

        for (int j = 0; j < arraylength; j++) {
            out.writeU8(array[j]);
        }
    }

    public
    boolean empty() {
        return types.size == 0;
    }

    public
    boolean contains(int typecode) {
        return types.containsKey(typecode);
    }
}
