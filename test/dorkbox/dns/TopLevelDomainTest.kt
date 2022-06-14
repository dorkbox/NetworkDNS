/*
 * Copyright 2021 dorkbox, llc
 * Copyright (C) 2014 ZeroTurnaround <support@zeroturnaround.com>
 * Contains fragments of code from Apache Commons Exec, rights owned
 * by Apache Software Foundation (ASF).
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

package dorkbox.dns

import org.junit.Assert
import org.junit.Test

class TopLevelDomainTest {
    @Test
    fun isTLD() {
        Assert.assertFalse(DNS.isTLD("www.espn.com"))
        Assert.assertFalse(DNS.isTLD("espn.com"))
        Assert.assertTrue(DNS.isTLD("com"))
        Assert.assertTrue(DNS.isTLD("co.uk"))
    }

    @Test
    fun withoutTLD() {
        Assert.assertEquals("espn", DNS.withoutTLD("espn.com"))
        Assert.assertEquals("www.espn", DNS.withoutTLD("www.espn.com"))
        Assert.assertEquals("a.b.c.www.espn", DNS.withoutTLD("a.b.c.www.espn.com"))
    }

    @Test
    fun extractSLD() {
        Assert.assertEquals("espn.com", DNS.extractSLD("espn.com"))
        Assert.assertEquals("espn.com", DNS.extractSLD("www.espn.com"))
        Assert.assertEquals("espn.com", DNS.extractSLD("a.b.c.www.espn.com"))
    }
}
