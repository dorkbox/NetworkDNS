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
package dorkbox.dns.dns.serverHandlers

import dorkbox.collections.LockFreeHashMap
import dorkbox.dns.DnsClient
import dorkbox.dns.dns.DnsEnvelope
import dorkbox.dns.dns.DnsServerResponse
import dorkbox.dns.dns.Name
import dorkbox.dns.dns.constants.DnsOpCode
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.constants.DnsResponseCode
import dorkbox.dns.dns.constants.DnsSection
import dorkbox.dns.dns.constants.Flags
import dorkbox.dns.dns.records.ARecord
import dorkbox.dns.dns.records.DnsMessage
import dorkbox.dns.dns.records.Update
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.util.concurrent.FutureListener
import org.slf4j.Logger
import java.net.InetSocketAddress

class DnsDecisionHandler(private val logger: Logger) : ChannelInboundHandlerAdapter() {
    private val aRecordMap = LockFreeHashMap<Name, List<ARecord>>()
    private val dnsClient: DnsClient = DnsClient()

    init {
        dnsClient.start()
    }

    /**
     * Adds a domain name query result, so clients that request the domain name will get the ipAddress
     *
     * @param domainName the domain name to have results for
     * @param aRecords the A records (can be multiple) to return for the requested domain name
     */
    fun addARecord(domainName: Name, aRecords: List<ARecord>) {
        aRecordMap[domainName] = aRecords
    }

    @Throws(Exception::class)
    override fun channelRead(context: ChannelHandlerContext, message: Any) {
        onChannelRead(context, message as DnsEnvelope)
    }

    @Throws(Exception::class)
    override fun exceptionCaught(context: ChannelHandlerContext, cause: Throwable) {
        logger.error("DecisionHandler#exceptionCaught", cause)
        super.exceptionCaught(context, cause)
    }

    private fun onChannelRead(context: ChannelHandlerContext, dnsMessage: DnsEnvelope) {
        val opcode = dnsMessage.header.opcode
        when (opcode) {
            DnsOpCode.QUERY -> {
                onQuery(context, dnsMessage, dnsMessage.recipient()!!)
                return
            }
            DnsOpCode.IQUERY -> {
                onIQuery(context, dnsMessage, dnsMessage.recipient())
                return
            }
            DnsOpCode.NOTIFY -> {
                onNotify(context, dnsMessage, dnsMessage.recipient()!!)
                return
            }
            DnsOpCode.STATUS -> {
                onStatus(context, dnsMessage, dnsMessage.recipient())
                return
            }
            DnsOpCode.UPDATE -> {
                onUpdate(context, dnsMessage as Update, dnsMessage.recipient())
                return
            }
            else -> logger.error(
                "Unknown DNS opcode {} from {}", opcode, context.channel().remoteAddress()
            )
        }
    }

    private fun onIQuery(context: ChannelHandlerContext, dnsQuestion: DnsMessage, recipient: InetSocketAddress?) {
        System.err.println("DECISION HANDLER READ")
        System.err.println(dnsQuestion)
    }

    private fun onNotify(context: ChannelHandlerContext, dnsQuestion: DnsMessage, recipient: InetSocketAddress) {
        System.err.println("DECISION HANDLER READ")
        System.err.println(dnsQuestion)
    }

    private fun onQuery(context: ChannelHandlerContext, dnsQuestion: DnsMessage, recipient: InetSocketAddress) {
        // either I have an answer, or I don't (and have to forward to another DNS server
        // it might be more than 1 question...
        val header = dnsQuestion.header
        val count = header.getCount(DnsSection.QUESTION)

        // we don't support more than 1 question at a time.
        if (count == 1) {
            val sectionArray = dnsQuestion.getSectionArray(DnsSection.QUESTION)
            val dnsRecord = sectionArray[0]
            val name = dnsRecord.name
            val ttl = dnsRecord.ttl
            val type = dnsRecord.type


            // what type of record? A, AAAA, MX, PTR, etc?
            if (DnsRecordType.A == type) {
                val resolver = dnsClient.resolver
                val domainName = name.toString(true)

                // check to see if we have it in our local hosts file
                val inetAddress = resolver!!.resolveHostsFileEntry(domainName)
                if (inetAddress != null) {
                    val dnsResponse = DnsServerResponse(
                        dnsQuestion, context.channel().localAddress() as InetSocketAddress, recipient
                    )

                    val responseHeader = dnsResponse.header
                    responseHeader.setFlag(Flags.QR)
                    responseHeader.rcode = DnsResponseCode.NOERROR
                    dnsResponse.addRecord(dnsRecord, DnsSection.QUESTION)

                    val aRecord = ARecord(name, dnsRecord.dclass, ttl, inetAddress)
                    dnsResponse.addRecord(aRecord, DnsSection.ANSWER)
                    context.channel().write(dnsResponse)
                    return
                }


                // check our local cache
                val records = aRecordMap[name]
                if (records != null) {
                    val dnsResponse = DnsServerResponse(
                        dnsQuestion, context.channel().localAddress() as InetSocketAddress, recipient
                    )
                    val responseHeader = dnsResponse.header
                    responseHeader.setFlag(Flags.QR)
                    responseHeader.rcode = DnsResponseCode.NOERROR
                    dnsResponse.addRecord(dnsRecord, DnsSection.QUESTION)

                    for (record in records) {
                        dnsResponse.addRecord(record, DnsSection.ANSWER)
                        logger.debug("Writing A record response: {}", record.address)
                    }

                    context.channel().write(dnsResponse)
                    return
                } else {
                    // have to send this on to the forwarder
                    logger.debug("Sending DNS query to the forwarder...")


                    // use "resolve", since it handles A/AAAA records + redirects correctly
                    resolver.resolveAll(domainName).addListener(FutureListener { future ->
                            val resolvedAddresses = future.now
                            val dnsResponse = DnsServerResponse(
                                dnsQuestion, context.channel().localAddress() as InetSocketAddress, recipient
                            )

                            val responseHeader = dnsResponse.header
                            responseHeader.setFlag(Flags.QR)
                            dnsResponse.addRecord(dnsRecord, DnsSection.QUESTION)

                            if (resolvedAddresses == null || resolvedAddresses.isEmpty()) {
                                responseHeader.rcode = DnsResponseCode.NXDOMAIN
                            } else {
                                responseHeader.rcode = DnsResponseCode.NOERROR

                                val records = ArrayList<ARecord>()
                                for (i in resolvedAddresses.indices) {
                                    val resolvedAddress = resolvedAddresses[i]
                                    val record = ARecord(name, dnsRecord.dclass, ttl, resolvedAddress!!)
                                    records.add(record)
                                    dnsResponse.addRecord(record, DnsSection.ANSWER)
                                }


                                // we got here because there were no cached records in our record map -- so we save them!
                                // duplicates are not an issue because they will always be the same answer
                                aRecordMap[name] = records
                            }
                            context.channel().write(dnsResponse)
                        })
                }
            }
            return
        }
        val sectionArray = dnsQuestion.getSectionArray(DnsSection.QUESTION)
        val dnsRecord = sectionArray[0]
        System.err.println(dnsRecord)
    }

    private fun onStatus(context: ChannelHandlerContext, dnsQuestion: DnsMessage, recipient: InetSocketAddress?) {
        System.err.println("DECISION HANDLER READ")
        System.err.println(dnsQuestion)
    }

    private fun onUpdate(context: ChannelHandlerContext, dnsUpdate: Update?, recipient: InetSocketAddress?) {
        System.err.println("DECISION HANDLER READ")
        System.err.println(dnsUpdate)
    }

    fun stop() {
        dnsClient.stop()
    }
}
