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

import java.net.InetAddress;
import java.net.UnknownHostException;

import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.exceptions.TextParseException;
import dorkbox.dns.dns.utils.Address;
import dorkbox.dns.dns.utils.ReverseMap;
import junit.framework.TestCase;

public
class ReverseMapTest extends TestCase {
    public
    void test_fromAddress_ipv4() throws UnknownHostException, TextParseException {
        Name exp = Name.fromString("1.0.168.192.in-addr.arpa.");
        String addr = "192.168.0.1";
        assertEquals(exp, ReverseMap.fromAddress(addr));

        assertEquals(exp, ReverseMap.fromAddress(addr, Address.IPv4));
        assertEquals(exp, ReverseMap.fromAddress(InetAddress.getByName(addr)));
        assertEquals(exp, ReverseMap.fromAddress(new byte[] {(byte) 192, (byte) 168, (byte) 0, (byte) 1}));
        assertEquals(exp, ReverseMap.fromAddress(new int[] {192, 168, 0, 1}));
    }

    public
    void test_fromAddress_ipv6() throws UnknownHostException, TextParseException {
        Name exp = Name.fromString("4.3.3.7.0.7.3.0.E.2.A.8.9.1.3.1.3.D.8.0.3.A.5.8.8.B.D.0.1.0.0.2.ip6.arpa.");
        String addr = "2001:0db8:85a3:08d3:1319:8a2e:0370:7334";
        byte[] dat = new byte[] {(byte) 32, (byte) 1, (byte) 13, (byte) 184, (byte) 133, (byte) 163, (byte) 8, (byte) 211, (byte) 19,
                                 (byte) 25, (byte) 138, (byte) 46, (byte) 3, (byte) 112, (byte) 115, (byte) 52};
        int[] idat = new int[] {32, 1, 13, 184, 133, 163, 8, 211, 19, 25, 138, 46, 3, 112, 115, 52};


        assertEquals(exp, ReverseMap.fromAddress(addr, Address.IPv6));
        assertEquals(exp, ReverseMap.fromAddress(InetAddress.getByName(addr)));
        assertEquals(exp, ReverseMap.fromAddress(dat));
        assertEquals(exp, ReverseMap.fromAddress(idat));
    }

    public
    void test_fromAddress_invalid() {
        try {
            ReverseMap.fromAddress("A.B.C.D", Address.IPv4);
            fail("UnknownHostException not thrown");
        } catch (UnknownHostException e) {
        }
        try {
            ReverseMap.fromAddress(new byte[0]);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
        try {
            ReverseMap.fromAddress(new byte[3]);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
        try {
            ReverseMap.fromAddress(new byte[5]);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
        try {
            ReverseMap.fromAddress(new byte[15]);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
        try {
            ReverseMap.fromAddress(new byte[17]);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }

        try {
            int[] dat = new int[] {0, 1, 2, 256};
            ReverseMap.fromAddress(dat);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException e) {
        }
    }
}
