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

import java.io.IOException;

import dorkbox.dns.dns.exceptions.InvalidDClassException;
import dorkbox.dns.dns.exceptions.InvalidTTLException;
import dorkbox.dns.dns.exceptions.InvalidTypeException;
import dorkbox.dns.dns.exceptions.NameTooLongException;
import dorkbox.dns.dns.exceptions.RelativeNameException;
import dorkbox.dns.dns.exceptions.TextParseException;
import dorkbox.dns.dns.exceptions.WireParseException;
import dorkbox.dns.dns.exceptions.ZoneTransferException;
import junit.framework.TestCase;

public
class ExceptionTest extends TestCase {
    public
    void test_InvalidDClassException() {
        IllegalArgumentException e = new InvalidDClassException(10);
        assertEquals("Invalid DNS class: 10", e.getMessage());
    }

    public
    void test_InvalidTTLException() {
        IllegalArgumentException e = new InvalidTTLException(32345);
        assertEquals("Invalid DNS TTL: 32345", e.getMessage());
    }

    public
    void test_InvalidTypeException() {
        IllegalArgumentException e = new InvalidTypeException(32345);
        assertEquals("Invalid DNS type: 32345", e.getMessage());
    }

    public
    void test_NameTooLongException() {
        WireParseException e = new NameTooLongException();
        assertNull(e.getMessage());

        e = new NameTooLongException("This is my too long name");
        assertEquals("This is my too long name", e.getMessage());
    }

    public
    void test_RelativeNameException() throws TextParseException {
        IllegalArgumentException e = new RelativeNameException("This is my relative name");
        assertEquals("This is my relative name", e.getMessage());

        e = new RelativeNameException(Name.Companion.fromString("relative"));
        assertEquals("'relative' is not an absolute name", e.getMessage());
    }

    public
    void test_TextParseException() {
        IOException e = new TextParseException();
        assertNull(e.getMessage());

        e = new TextParseException("This is my message");
        assertEquals("This is my message", e.getMessage());
    }

    public
    void test_WireParseException() {
        IOException e = new WireParseException();
        assertNull(e.getMessage());

        e = new WireParseException("This is my message");
        assertEquals("This is my message", e.getMessage());
    }

    public
    void test_ZoneTransferException() {
        Exception e = new ZoneTransferException();
        assertNull(e.getMessage());

        e = new ZoneTransferException("This is my message");
        assertEquals("This is my message", e.getMessage());
    }
}
