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

import dorkbox.dns.dns.Name.Companion.fromString
import dorkbox.dns.dns.exceptions.TextParseException
import dorkbox.dns.dns.utils.Options.set
import junit.framework.TestCase

class CompressionTest : TestCase() {
    public override fun setUp() {
        set("verbosecompression")
    }

    @Throws(TextParseException::class)
    fun test() {
        val c = Compression()
        val n = fromString("www.amazon.com.")
        c.add(10, n)
        assertEquals(10, c[n])

        val n2 = fromString("www.cnn.com.")
        c.add(10, n2)
        assertEquals(10, c[n2])
    }
}
