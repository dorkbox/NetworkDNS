// -*- Java -*-
//
// Copyright (c) 2005, Matthew J. Rutherford <rutherfo@cs.colorado.edu>
// Copyright (c) 2005, University of Colorado at Boulder
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
// 
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
// 
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
// 
// * Neither the name of the University of Colorado at Boulder nor the
//   names of its contributors may be used to endorse or promote
//   products derived from this software without specific prior written
//   permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
package dorkbox.network.dns;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.ConsoleAppender;
import dorkbox.netUtil.IPv4;
import dorkbox.netUtil.IPv6;
import dorkbox.network.dns.utils.Address;
import junit.framework.TestCase;

public
class AddressTest extends TestCase {
    static {
        // assume SLF4J is bound to logback in the current environment
        Logger rootLogger = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        LoggerContext context = rootLogger.getLoggerContext();
        final JoranConfigurator jc = new JoranConfigurator();
        jc.setContext(context);
        context.reset(); // override default configuration

        rootLogger.setLevel(Level.DEBUG);

        // we only want error messages
        ((Logger) LoggerFactory.getLogger("io.netty.util.internal")).setLevel(Level.ERROR);


        PatternLayoutEncoder encoder = new PatternLayoutEncoder();
        encoder.setContext(context);
        encoder.setPattern("%date{HH:mm:ss.SSS}  %-5level [%logger{35}] %msg%n");
        encoder.start();

        final ConsoleAppender<ILoggingEvent> consoleAppender = new ConsoleAppender<ILoggingEvent>();
        consoleAppender.setContext(context);
        consoleAppender.setEncoder(encoder);
        consoleAppender.start();
        rootLogger.addAppender(consoleAppender);
    }

    public
    void test_toByteArray_IPv4() {
        byte[] exp = new byte[] {(byte) 198, (byte) 121, (byte) 10, (byte) 234};
        byte[] ret = IPv4.INSTANCE.toBytes("198.121.10.234");
        assertEquals(exp, ret);

        exp = new byte[] {0, 0, 0, 0};
        ret = IPv4.INSTANCE.toBytes("0.0.0.0");
        assertEquals(exp, ret);

        exp = new byte[] {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
        ret = IPv4.INSTANCE.toBytes("255.255.255.255");
        assertEquals(exp, ret);
    }

    private
    void assertEquals(byte[] exp, byte[] act) {
        assertTrue(Arrays.equals(exp, act));
    }

    public
    void test_toByteArray_IPv4_invalid() {
        assertNull(IPv4.INSTANCE.toBytesOrNull("A.B.C.D"));

        assertNull(IPv4.INSTANCE.toBytesOrNull("128..."));
        assertNull(IPv4.INSTANCE.toBytesOrNull("128.121"));
        assertNull(IPv4.INSTANCE.toBytesOrNull("128.111.8"));
        assertNull(IPv4.INSTANCE.toBytesOrNull("128.198.10."));

        assertNull(IPv4.INSTANCE.toBytesOrNull("128.121.90..10"));
        assertNull(IPv4.INSTANCE.toBytesOrNull("128.121..90.10"));
        assertNull(IPv4.INSTANCE.toBytesOrNull("128..121.90.10"));
        assertNull(IPv4.INSTANCE.toBytesOrNull(".128.121.90.10"));

        assertNull(IPv4.INSTANCE.toBytesOrNull("128.121.90.256"));
        assertNull(IPv4.INSTANCE.toBytesOrNull("128.121.256.10"));
        assertNull(IPv4.INSTANCE.toBytesOrNull("128.256.90.10"));
        assertNull(IPv4.INSTANCE.toBytesOrNull("256.121.90.10"));

        assertNull(IPv4.INSTANCE.toBytesOrNull("128.121.90.-1"));
        assertNull(IPv4.INSTANCE.toBytesOrNull("128.121.-1.10"));
        assertNull(IPv4.INSTANCE.toBytesOrNull("128.-1.90.10"));
        assertNull(IPv4.INSTANCE.toBytesOrNull("-1.121.90.10"));

        assertNull(IPv4.INSTANCE.toBytesOrNull("120.121.90.10.10"));

        // assertNull(IPv4.INSTANCE.toBytesOrNull("120.121.90.010")); // this is valid!
        // assertNull(IPv4.INSTANCE.toBytesOrNull("120.121.090.10")); // this is valid!
        // assertNull(IPv4.INSTANCE.toBytesOrNull("120.021.90.10")); // this is valid!
        // assertNull(IPv4.INSTANCE.toBytesOrNull("020.121.90.10")); // this is valid!

        assertNull(IPv4.INSTANCE.toBytesOrNull("1120.121.90.10"));
        assertNull(IPv4.INSTANCE.toBytesOrNull("120.2121.90.10"));
        assertNull(IPv4.INSTANCE.toBytesOrNull("120.121.4190.10"));
        assertNull(IPv4.INSTANCE.toBytesOrNull("120.121.190.1000"));

        assertNull(IPv4.INSTANCE.toBytesOrNull(""));
    }

    public
    void test_toByteArray_IPv6() {
        byte[] exp;
        byte[] ret;

        exp = new byte[] {(byte) 32, (byte) 1, (byte) 13, (byte) 184, (byte) 133, (byte) 163, (byte) 8, (byte) 211, (byte) 19,
                          (byte) 25, (byte) 138, (byte) 46, (byte) 3, (byte) 112, (byte) 115, (byte) 52};
        ret = IPv6.INSTANCE.toBytesOrNull("2001:0db8:85a3:08d3:1319:8a2e:0370:7334");
        assertEquals(exp, ret);
        ret = IPv6.INSTANCE.toBytesOrNull("2001:db8:85a3:8d3:1319:8a2e:370:7334");
        assertEquals(exp, ret);
        ret = IPv6.INSTANCE.toBytesOrNull("2001:DB8:85A3:8D3:1319:8A2E:370:7334");
        assertEquals(exp, ret);

        exp = new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        ret = IPv6.INSTANCE.toBytesOrNull("0:0:0:0:0:0:0:0");
        assertEquals(exp, ret);

        exp = new byte[] {(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                          (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF};
        ret = IPv6.INSTANCE.toBytesOrNull("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF");
        assertEquals(exp, ret);

        exp = new byte[] {(byte) 32, (byte) 1, (byte) 13, (byte) 184, (byte) 0, (byte) 0, (byte) 8, (byte) 211, (byte) 19, (byte) 25,
                          (byte) 138, (byte) 46, (byte) 3, (byte) 112, (byte) 115, (byte) 52};
        ret = IPv6.INSTANCE.toBytesOrNull("2001:0db8:0000:08d3:1319:8a2e:0370:7334");
        assertEquals(exp, ret);

        ret = IPv6.INSTANCE.toBytesOrNull("2001:0db8::08d3:1319:8a2e:0370:7334");
        assertEquals(exp, ret);

        exp = new byte[] {(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 133, (byte) 163, (byte) 8, (byte) 211, (byte) 19, (byte) 25,
                          (byte) 138, (byte) 46, (byte) 3, (byte) 112, (byte) 115, (byte) 52};
        ret = IPv6.INSTANCE.toBytesOrNull("0000:0000:85a3:08d3:1319:8a2e:0370:7334");
        assertEquals(exp, ret);
        ret = IPv6.INSTANCE.toBytesOrNull("::85a3:08d3:1319:8a2e:0370:7334");
        assertEquals(exp, ret);

        exp = new byte[] {(byte) 32, (byte) 1, (byte) 13, (byte) 184, (byte) 133, (byte) 163, (byte) 8, (byte) 211, (byte) 19, (byte) 25,
                          (byte) 138, (byte) 46, (byte) 0, (byte) 0, (byte) 0, (byte) 0};
        ret = IPv6.INSTANCE.toBytesOrNull("2001:0db8:85a3:08d3:1319:8a2e:0:0");
        assertEquals(exp, ret);

        ret = IPv6.INSTANCE.toBytesOrNull("2001:0db8:85a3:08d3:1319:8a2e::");
        assertEquals(exp, ret);

        exp = new byte[] {(byte) 32, (byte) 1, (byte) 13, (byte) 184, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0,
                          (byte) 0, (byte) 3, (byte) 112, (byte) 115, (byte) 52};
        ret = IPv6.INSTANCE.toBytesOrNull("2001:0db8:0000:0000:0000:0000:0370:7334");
        assertEquals(exp, ret);
        ret = IPv6.INSTANCE.toBytesOrNull("2001:0db8:0:0:0:0:0370:7334");
        assertEquals(exp, ret);
        ret = IPv6.INSTANCE.toBytesOrNull("2001:0db8::0:0370:7334");
        assertEquals(exp, ret);
        ret = IPv6.INSTANCE.toBytesOrNull("2001:db8::370:7334");
        assertEquals(exp, ret);

        exp = new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1, -64, -88, 89, 9};
        ret = IPv6.INSTANCE.toBytesOrNull("0000:0000:0000:0000:0000:0000:192.168.89.9");
        assertEquals(exp, ret);

        ret = IPv6.INSTANCE.toBytesOrNull("2001:0db8:85a3:08d3:1319:0000:192.168.89.9");
        assertEquals(null, ret);

        exp = new byte[] {(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) -1,
                          (byte) -1, (byte) 0xC0, (byte) 0xA8, (byte) 0x59, (byte) 0x09};
        ret = IPv6.INSTANCE.toBytesOrNull("::192.168.89.9");
        assertEquals(exp, ret);
    }

    public
    void test_toByteArray_IPv6_invalid() {
        // not enough groups
        assertNull(IPv6.INSTANCE.toBytesOrNull("2001:0db8:85a3:08d3:1319:8a2e:0370"));
        // too many groups
        assertNull(IPv6.INSTANCE.toBytesOrNull("2001:0db8:85a3:08d3:1319:8a2e:0370:193A:BCdE"));
        // invalid letter
        assertNull(IPv6.INSTANCE.toBytesOrNull("2001:0gb8:85a3:08d3:1319:8a2e:0370:9819"));
        assertNull(IPv6.INSTANCE.toBytesOrNull("lmno:0bb8:85a3:08d3:1319:8a2e:0370:9819"));
        assertNull(IPv6.INSTANCE.toBytesOrNull("11ab:0ab8:85a3:08d3:1319:8a2e:0370:qrst"));
        // three consecutive colons
        assertNull(IPv6.INSTANCE.toBytesOrNull("11ab:0ab8:85a3:08d3:::"));
        // IPv4 in the middle
        assertNull(IPv6.INSTANCE.toBytesOrNull("2001:0ab8:192.168.0.1:1319:8a2e:0370:9819"));
        // invalid IPv4
        assertNull(IPv6.INSTANCE.toBytesOrNull("2001:0ab8:1212:AbAb:8a2e:345.12.22.1"));
        // group with too many digits
        assertNull(IPv6.INSTANCE.toBytesOrNull("2001:0ab8:85a3:128d3:1319:8a2e:0370:9819"));

    }

    public
    void test_toArray() {
        int[] exp = new int[] {1, 2, 3, 4};
        int[] ret = IPv4.INSTANCE.toInts("1.2.3.4");
        assertEquals(exp, ret);

        exp = new int[] {0, 0, 0, 0};
        ret = IPv4.INSTANCE.toInts("0.0.0.0");
        assertEquals(exp, ret);

        exp = new int[] {255, 255, 255, 255};
        ret = IPv4.INSTANCE.toInts("255.255.255.255");
        assertEquals(exp, ret);
    }

    private
    void assertEquals(int[] exp, int[] act) {
        assertEquals(exp.length, act.length);
        for (int i = 0; i < exp.length; ++i) {
            assertEquals("i=" + i, exp[i], act[i]);
        }
    }

    public
    void test_toArray_invalid() {
        assertNull(IPv4.INSTANCE.toBytesOrNull("128.121.1"));

        assertNull(IPv4.INSTANCE.toBytesOrNull(""));
    }

    public
    void test_isDottedQuad() {
        assertTrue(IPv4.INSTANCE.isValid("1.2.3.4"));
        assertFalse(IPv4.INSTANCE.isValid("256.2.3.4"));
    }

    public
    void test_toDottedQuad() {
        assertEquals("128.176.201.1", IPv4.INSTANCE.toString(new byte[] {(byte) 128, (byte) 176, (byte) 201, (byte) 1}));
        assertEquals("200.1.255.128", IPv4.INSTANCE.toString(new int[] {200, 1, 255, 128}));
    }

    public
    void test_addressLength() {
        assertEquals(4, IPv4.INSTANCE.getLength());
        assertEquals(16, IPv6.INSTANCE.getLength());
    }

    public
    void test_getByName() throws UnknownHostException {
        InetAddress out = Address.getByName("128.145.198.231");
        assertEquals("128.145.198.231", out.getHostAddress());

        out = Address.getByName("a.root-servers.net");
        assertEquals("198.41.0.4", out.getHostAddress());
    }

    public
    void test_getByName_invalid() throws UnknownHostException {
        try {
            Address.getByName("example.invalid");
            fail("UnknownHostException not thrown");
        } catch (UnknownHostException ignored) {
        }

        try {
            InetAddress byName = Address.getByName("");
            assertEquals("127.0.0.1", byName.getHostAddress());
        } catch (UnknownHostException ignored) {
            fail("UnknownHostException thrown");
        }
    }

    public
    void test_getAllByName() throws UnknownHostException {
        InetAddress[] out;

        out = Address.getAllByName("128.145.198.231");
        assertEquals(1, out.length);
        assertEquals("128.145.198.231", out[0].getHostAddress());

        out = Address.getAllByName("a.root-servers.net");
        assertTrue(out.length == 2);
        assertEquals("198.41.0.4", out[0].getHostAddress());
        assertEquals("2001:503:ba3e:0:0:0:2:30", out[1].getHostAddress());

        out = Address.getAllByName("cnn.com");
        assertTrue(out.length > 1);
        for (int i = 0; i < out.length; ++i) {
            String hostName = out[i].getHostName();
            assertTrue(hostName.endsWith("cnn.com"));
        }
    }

    public
    void test_getAllByName_invalid() throws UnknownHostException {
        try {
            Address.getAllByName("example.invalid");
            fail("UnknownHostException not thrown");
        } catch (UnknownHostException ignored) {
        }

        try {
            InetAddress[] byName = Address.getAllByName("");
            assertEquals("127.0.0.1", byName[0].getHostAddress());
            assertEquals("0:0:0:0:0:0:0:1", byName[1].getHostAddress());
        } catch (UnknownHostException ignored) {
            fail("UnknownHostException thrown");
        }
    }

    public
    void test_familyOf() throws UnknownHostException {
        assertTrue(IPv4.INSTANCE.isFamily(InetAddress.getByName("192.168.0.1")));
        assertTrue(IPv6.INSTANCE.isFamily(InetAddress.getByName("1:2:3:4:5:6:7:8")));

        try {
            Address.familyOf(null);
            fail("IllegalArgumentException not thrown");
        } catch (IllegalArgumentException ignored) {
        }
    }

    public
    void test_getHostName() throws UnknownHostException {
        InetAddress byName = InetAddress.getByName("198.41.0.4");
        String out = Address.getHostName(byName);
        assertEquals("a.root-servers.net.", out);

        try {
            Address.getHostName(InetAddress.getByName("192.168.1.1"));
            fail("UnknownHostException not thrown");
        } catch (UnknownHostException ignored) {
        }
    }
}
