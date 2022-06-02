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
package dorkbox.dns.dns.zone

import dorkbox.dns.dns.Name
import dorkbox.dns.dns.server.Response
import java.net.InetAddress

class ForwardZone : AbstractZone {
    protected var forwarders: MutableList<InetAddress> = ArrayList()

    constructor(name: Name?) : super(ZoneType.forward, name!!) {}
    constructor(dnsclass: Int, name: Name?) : super(ZoneType.forward, dnsclass, name!!) {}

    fun addForwardHost(host: InetAddress) {
        forwarders.add(host)
    }

    override fun find(qname: Name, recordType: Int): Response? {
        // TODO Auto-generated method stub
        return null
    }
}
