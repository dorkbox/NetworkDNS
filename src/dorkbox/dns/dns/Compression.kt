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

import dorkbox.dns.dns.utils.Options.check

/**
 * DNS Name Compression object.
 *
 * @author Brian Wellington
 * @see DnsMessage
 *
 * @see Name
 */
class Compression {
    companion object {
        private const val TABLE_SIZE = 17
        private const val MAX_POINTER = 0x3FFF
    }

    private val table = arrayOfNulls<Entry?>(TABLE_SIZE)
    private val verbose = check("verbosecompression")

    private class Entry {
        var name: Name? = null
        var pos = 0
        var next: Entry? = null
    }

    /**
     * Adds a compression entry mapping a name to a position in a message.
     *
     * @param pos The position at which the name is added.
     * @param name The name being added to the message.
     */
    fun add(pos: Int, name: Name) {
        if (pos > MAX_POINTER) {
            return
        }
        val row = (name.hashCode() and 0x7FFFFFFF) % TABLE_SIZE

        val entry = Entry()
        entry.name = name
        entry.pos = pos
        entry.next = table[row]
        table[row] = entry

        if (verbose) {
            System.err.println("Adding $name at $pos")
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
    operator fun get(name: Name): Int {
        val row = (name.hashCode() and 0x7FFFFFFF) % TABLE_SIZE
        var pos = -1
        var entry = table[row]

        while (entry != null) {
            if (entry.name!!.equals(name)) {
                pos = entry.pos
            }
            entry = entry.next
        }
        if (verbose) {
            System.err.println("Looking for $name, found $pos")
        }
        return pos
    }
}
