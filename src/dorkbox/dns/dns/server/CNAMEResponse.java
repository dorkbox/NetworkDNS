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
package dorkbox.dns.dns.server;


import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsResponseCode;
import dorkbox.dns.dns.records.DnsMessage;
import dorkbox.dns.dns.records.DnsRecord;

public class CNAMEResponse extends DefaultResponse {
	final Name cname;
	final int qtype;

	public CNAMEResponse(DnsRecord cname, int queryType) {
		super(DnsResponseCode.NOERROR);
		this.cname = cname.getName();
		this.qtype = queryType;
	}

	@Override
	public void postProcess(DnsMessage message) {
        System.err.println("WHAT?");

		// context.response().answer().add(this.cname);
		// Response r = context.resolve(this.cname.oneName(), this.qtype);
		// r.postProcess(context);
	}
}
