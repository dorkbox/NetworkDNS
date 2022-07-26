package org.handwerkszeug.dns.server;

import dorkbox.network.DnsServer;

public class DNSServerTest {

    public static
    void main(String[] args) {
        DnsServer dnsServer = new DnsServer("127.0.0.1", 2053);
        dnsServer.bind();
    }

	//@Test // Disabled as you need to be a super user or have the correct permissions to bind to port 53
	public void testMain() throws Exception {
        DnsServer dnsServer = new DnsServer("127.0.0.1", 53);
        dnsServer.bind();
	}
}
