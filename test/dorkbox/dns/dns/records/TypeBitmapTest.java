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

import dorkbox.dns.dns.records.TypeBitmap;
import junit.framework.TestCase;

public
class TypeBitmapTest extends TestCase {
    public
    void test_empty() {
        TypeBitmap typeBitmap = new TypeBitmap(new int[] {});
        assertEquals(typeBitmap.toString(), "");
    }

    public
    void test_typeA() {
        TypeBitmap typeBitmap = new TypeBitmap(new int[] {1});
        assertEquals(typeBitmap.toString(), "A");
    }

    public
    void test_typeNSandSOA() {
        TypeBitmap typeBitmap = new TypeBitmap(new int[] {2, 6});
        assertEquals(typeBitmap.toString(), "NS SOA");
    }
}
