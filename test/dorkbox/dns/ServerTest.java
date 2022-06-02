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

package dorkbox.dns;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

/**
 *
 */
public
class ServerTest {
    public static
    void main(String[] args) {
        // DnsServer server = new DnsServer("localhost", 2053);
        // server.aRecord("google.com", DnsClass.IN, 10, "127.0.0.1");
        // server.bind();

        // MasterZone zone = new MasterZone();

        // server.bind(false);


        DnsClient client = new DnsClient("localhost", 2053);
        List<InetAddress> resolve = null;
        try {
            resolve = client.resolve("google.com");
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        System.err.println("RESOLVED: " + resolve);
        client.stop();
        // server.stop();
    }
}
