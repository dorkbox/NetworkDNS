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
package dorkbox.dns.dns.server

import dorkbox.dns.dns.Name
import dorkbox.dns.dns.constants.DnsResponseCode
import dorkbox.dns.dns.records.DnsMessage
import dorkbox.dns.dns.records.DnsRecord

class DNAMEResponse(dname: DnsRecord, qname: Name, qtype: Int) : DefaultResponse(DnsResponseCode.NOERROR) {
    val dname: Name
    val qname: Name
    val qtype: Int

    init {
        this.dname = dname.name
        this.qname = qname
        this.qtype = qtype
    }

    override fun postProcess(context: DnsMessage) {
        System.err.println("WWHAT?")
        // DNSMessage res = context.response();
        // res.answer().add(this.dname);
        // Name name = this.qname.replace(this.dname.name(), this.dname.oneName());
        // if (name == null) {
        // 	context.response().header().rcode(RCode.YXDomain);
        // } else {
        // 	SingleNameRecord cname = new SingleNameRecord(RRType.CNAME, name);
        // 	cname.name(this.qname);
        // 	res.answer().add(cname);
        // 	res.header().aa(true);
        // 	Response r = context.resolve(name, this.qtype);
        // 	r.postProcess(context);
        // }
    }
}
