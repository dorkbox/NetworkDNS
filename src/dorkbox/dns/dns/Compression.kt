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

package dorkbox.dns.dns;

import dorkbox.dns.dns.records.DnsMessage;
import dorkbox.dns.dns.utils.Options;

/**
 * DNS Name Compression object.
 *
 * @author Brian Wellington
 * @see DnsMessage
 * @see Name
 */

public
class Compression {

    private static final int TABLE_SIZE = 17;
    private static final int MAX_POINTER = 0x3FFF;
    private Entry[] table;
    private boolean verbose = Options.check("verbosecompression");


    private static
    class Entry {
        Name name;
        int pos;
        Entry next;
    }

    /**
     * Creates a new Compression object.
     */
    public
    Compression() {
        table = new Entry[TABLE_SIZE];
    }

    /**
     * Adds a compression entry mapping a name to a position in a message.
     *
     * @param pos The position at which the name is added.
     * @param name The name being added to the message.
     */
    public
    void add(int pos, Name name) {
        if (pos > MAX_POINTER) {
            return;
        }
        int row = (name.hashCode() & 0x7FFFFFFF) % TABLE_SIZE;
        Entry entry = new Entry();
        entry.name = name;
        entry.pos = pos;
        entry.next = table[row];
        table[row] = entry;
        if (verbose) {
            System.err.println("Adding " + name + " at " + pos);
        }
    }

    /**
     * Retrieves the position of the given name, if it has been previously
     * included in the message.
     *
     * @param name The name to find in the compression table.
     *
     * @return The position of the name, or -1 if not found.
     */
    public
    int get(Name name) {
        int row = (name.hashCode() & 0x7FFFFFFF) % TABLE_SIZE;
        int pos = -1;
        for (Entry entry = table[row]; entry != null; entry = entry.next) {
            if (entry.name.equals(name)) {
                pos = entry.pos;
            }
        }
        if (verbose) {
            System.err.println("Looking for " + name + ", found " + pos);
        }
        return pos;
    }

}
