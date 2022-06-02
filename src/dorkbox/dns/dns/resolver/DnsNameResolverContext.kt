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
package dorkbox.dns.dns.resolver

import dorkbox.dns.dns.DnsQuestion
import dorkbox.dns.dns.DnsQuestion.Companion.newResolveQuestion
import dorkbox.dns.dns.clientHandlers.DnsResponse
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.constants.DnsResponseCode
import dorkbox.dns.dns.constants.DnsSection
import dorkbox.dns.dns.records.AAAARecord
import dorkbox.dns.dns.records.ARecord
import dorkbox.dns.dns.records.CNAMERecord
import dorkbox.dns.dns.records.DnsMessage
import dorkbox.dns.dns.records.DnsRecord
import dorkbox.dns.dns.records.NSRecord
import dorkbox.dns.dns.resolver.addressProvider.DnsServerAddressStream
import dorkbox.dns.dns.resolver.addressProvider.DnsServerAddresses
import dorkbox.dns.dns.resolver.cache.DnsCache
import dorkbox.dns.dns.resolver.cache.DnsCacheEntry
import io.netty.channel.socket.InternetProtocolFamily
import io.netty.util.concurrent.Future
import io.netty.util.concurrent.FutureListener
import io.netty.util.concurrent.Promise
import io.netty.util.internal.ObjectUtil
import io.netty.util.internal.PlatformDependent
import io.netty.util.internal.StringUtil
import io.netty.util.internal.ThrowableUtil
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.UnknownHostException
import java.util.*

internal abstract class DnsNameResolverContext<T>(
    private val parent: DnsNameResolver,
    private val hostname: String,
    private val resolveCache: DnsCache,
    nameServerAddrs: DnsServerAddressStream
) {
    private val nameServerAddrs: DnsServerAddressStream
    private val maxAllowedQueries: Int
    private val resolvedInternetProtocolFamilies: Array<InternetProtocolFamily>
    private val queriesInProgress = Collections.newSetFromMap(IdentityHashMap<Future<DnsResponse>, Boolean>())
    private var resolvedEntries: MutableList<DnsCacheEntry>? = null
    private var allowedQueries: Int
    private var triedCNAME = false

    init {
        this.nameServerAddrs = ObjectUtil.checkNotNull(nameServerAddrs, "nameServerAddrs")
        maxAllowedQueries = parent.maxQueriesPerResolve()
        resolvedInternetProtocolFamilies = parent.resolvedInternetProtocolFamiliesUnsafe()
        allowedQueries = maxAllowedQueries
    }

    fun resolve(promise: Promise<T>) {
        if (parent.searchDomains().size == 0 || parent.ndots() == 0 || StringUtil.endsWith(hostname, '.')) {
            internalResolve(promise)
        } else {
            var dots = 0
            for (idx in hostname.length - 1 downTo 0) {
                if (hostname[idx] == '.' && ++dots >= parent.ndots()) {
                    internalResolve(promise)
                    return
                }
            }
            doSearchDomainQuery(0, object : FutureListener<T> {
                private var count = 1
                @Throws(Exception::class)
                override fun operationComplete(future: Future<T>) {
                    if (future.isSuccess) {
                        promise.trySuccess(future.now)
                    } else if (count < parent.searchDomains().size) {
                        doSearchDomainQuery(count++, this)
                    } else {
                        promise.tryFailure(SearchDomainUnknownHostException(future.cause(), hostname))
                    }
                }
            })
        }
    }

    private class SearchDomainUnknownHostException internal constructor(cause: Throwable, originalHostname: String) :
        UnknownHostException("Search domain query failed. Original hostname: '" + originalHostname + "' " + cause.message) {
        init {
            stackTrace = cause.stackTrace
        }

        override fun fillInStackTrace(): Throwable {
            return this
        }
    }

    private fun doSearchDomainQuery(count: Int, listener: FutureListener<T>) {
        val nextContext = newResolverContext(
            parent, hostname + '.' + parent.searchDomains()[count], resolveCache, nameServerAddrs
        )
        val nextPromise = parent.executor().newPromise<T>()
        nextPromise.addListener(listener)
        nextContext.internalResolve(nextPromise)
    }

    private fun internalResolve(promise: Promise<T>) {
        val nameServerAddressStream = getNameServers(hostname)
        val recordTypes = parent.resolveRecordTypes()
        assert(recordTypes.size > 0)
        val end = recordTypes.size - 1
        for (i in 0 until end) {
            if (!resolveQuery(hostname, recordTypes[i], nameServerAddressStream.duplicate(), promise)) {
                return
            }
        }
        resolveQuery(hostname, recordTypes[end], nameServerAddressStream, promise)
    }

    /**
     * Add an authoritative nameserver to the cache if its not a root server.
     */
    private fun addNameServerToCache(name: AuthoritativeNameServer, resolved: InetAddress, ttl: Long) {
        if (!name.isRootServer) {
            // Cache NS record if not for a root server as we should never cache for root servers.
            parent.authoritativeDnsServerCache().cache(name.domainName(), resolved, ttl, parent.ch.eventLoop())
        }
    }

    /**
     * Returns the [DnsServerAddressStream] that was cached for the given hostname or `null` if non
     * could be found.
     */
    private fun getNameServersFromCache(hostname: String): DnsServerAddressStream? {
        var hostname = hostname
        val len = hostname.length
        if (len == 0) {
            // We never cache for root servers.
            return null
        }

        // We always store in the cache with a trailing '.'.
        if (hostname[len - 1] != '.') {
            hostname += "."
        }
        var idx = hostname.indexOf('.')
        if (idx == hostname.length - 1) {
            // We are not interested in handling '.' as we should never serve the root servers from cache.
            return null
        }

        // We start from the closed match and then move down.
        while (true) {

            // Skip '.' as well.
            hostname = hostname.substring(idx + 1)
            val idx2 = hostname.indexOf('.')
            if (idx2 <= 0 || idx2 == hostname.length - 1) {
                // We are not interested in handling '.TLD.' as we should never serve the root servers from cache.
                return null
            }
            idx = idx2
            val entries = parent.authoritativeDnsServerCache()[hostname]
            if (entries != null && entries.isNotEmpty()) {
                return DnsServerAddresses.sequential(DnsCacheIterable(entries)).stream()
            }
        }
    }

    private inner class DnsCacheIterable internal constructor(private val entries: MutableList<DnsCacheEntry>) : Iterable<InetSocketAddress> {
        override fun iterator(): MutableIterator<InetSocketAddress> {
            return object : MutableIterator<InetSocketAddress> {
                var entryIterator = entries.iterator()
                override fun hasNext(): Boolean {
                    return entryIterator.hasNext()
                }

                override fun next(): InetSocketAddress {
                    val address = entryIterator.next().address()
                    return InetSocketAddress(address, parent.dnsRedirectPort(address))
                }

                override fun remove() {
                    entryIterator.remove()
                }
            }
        }
    }

    private fun resolveQuery(
        nameServerAddrStream: DnsServerAddressStream, nameServerAddrStreamIndex: Int, question: DnsQuestion, promise: Promise<T>
    ) {
        resolveQuery(
            nameServerAddrStream,
            nameServerAddrStreamIndex,
            question,
            parent.dnsQueryLifecycleObserverFactory()!!.newDnsQueryLifecycleObserver(question),
            promise
        )
    }

    private fun resolveQuery(
        nameServerAddrStream: DnsServerAddressStream,
        nameServerAddrStreamIndex: Int,
        question: DnsQuestion,
        queryLifecycleObserver: DnsQueryLifecycleObserver,
        promise: Promise<T>
    ) {
        // question should have refCnt=2
        if (nameServerAddrStreamIndex >= nameServerAddrStream.size() || allowedQueries == 0 || promise.isCancelled) {
            tryToFinishResolve(nameServerAddrStream, nameServerAddrStreamIndex, question, queryLifecycleObserver, promise)
            return
        }
        --allowedQueries
        val nameServerAddr = nameServerAddrStream.next()
        val writePromise = parent.ch.newPromise()
        val f = parent.query0(
            nameServerAddr, question, writePromise, parent.ch.eventLoop().newPromise()
        )
        queriesInProgress.add(f)
        queryLifecycleObserver.queryWritten(nameServerAddr, writePromise)
        f.addListener(object : FutureListener<DnsResponse> {
            override fun operationComplete(future: Future<DnsResponse>) {
                // future.result() should have refCnt=2
                // question should have refCnt=1
                queriesInProgress.remove(future)
                if (promise.isDone || future.isCancelled) {
                    queryLifecycleObserver.queryCancelled(allowedQueries)


                    // Check if we need to release the envelope itself. If the query was cancelled the getNow() will
                    // return null as well as the Future will be failed with a CancellationException.
                    val result = future.now
                    result?.release()
                    return
                }
                val envelope = future.now
                try {
                    if (future.isSuccess) {
                        onResponse(
                            nameServerAddrStream, nameServerAddrStreamIndex, question, envelope, queryLifecycleObserver, promise
                        )
                    } else {
                        // Server did not respond or I/O error occurred; try again.
                        queryLifecycleObserver.queryFailed(future.cause())

                        // query uses the question again...
                        question.retain()
                        resolveQuery(nameServerAddrStream, nameServerAddrStreamIndex + 1, question, promise)
                    }
                } finally {
                    // future.result() should have refCnt=2
                    // question should have refCnt=1
                    tryToFinishResolve(
                        nameServerAddrStream,
                        nameServerAddrStreamIndex,
                        question,  // queryLifecycleObserver has already been terminated at this point so we must
                        // not allow it to be terminated again by tryToFinishResolve.
                        NoopDnsQueryLifecycleObserver.INSTANCE,
                        promise
                    )
                }
            }
        })
    }

    fun onResponse(
        nameServerAddrStream: DnsServerAddressStream,
        nameServerAddrStreamIndex: Int,
        question: DnsQuestion,
        response: DnsResponse,
        queryLifecycleObserver: DnsQueryLifecycleObserver,
        promise: Promise<T>
    ) {
        val code = response.header.rcode
        if (code == DnsResponseCode.NOERROR) {
            if (handleRedirect(question, response, queryLifecycleObserver, promise)) {
                // Was a redirect so return here as everything else is handled in handleRedirect(...)
                return
            }

            val type = question.question!!.type
            if (type == DnsRecordType.A || type == DnsRecordType.AAAA) {
                onResponseAorAAAA(type, question, response, queryLifecycleObserver, promise)
            } else if (type == DnsRecordType.CNAME) {
                onResponseCNAME(question, response, queryLifecycleObserver, promise)
            } else {
                queryLifecycleObserver.queryFailed(UNRECOGNIZED_TYPE_QUERY_FAILED_EXCEPTION)
            }
            return
        }

        // Retry with the next server if the server did not tell us that the domain does not exist.
        if (code != DnsResponseCode.NXDOMAIN) {
            resolveQuery(
                nameServerAddrStream, nameServerAddrStreamIndex + 1, question, queryLifecycleObserver.queryNoAnswer(code), promise
            )
        } else {
            queryLifecycleObserver.queryFailed(NXDOMAIN_QUERY_FAILED_EXCEPTION)
        }
    }

    /**
     * Handles a redirect answer if needed and returns `true` if a redirect query has been made.
     */
    private fun handleRedirect(
        question: DnsQuestion, response: DnsResponse, queryLifecycleObserver: DnsQueryLifecycleObserver, promise: Promise<T>
    ): Boolean {

        // Check if we have answers, if not this may be an non authority NS and so redirects must be handled.
        val answerArray = response.getSectionArray(DnsSection.ANSWER)
        if (answerArray.isEmpty()) {
            val serverNames = extractAuthoritativeNameServers(question.question!!.name.toString(), response)
            if (serverNames != null) {
                val nameServers: MutableList<InetSocketAddress> = ArrayList(serverNames.size())

                val additionalArray = response.getSectionArray(DnsSection.ADDITIONAL)
                for (i in additionalArray.indices) {
                    val r = additionalArray[i]
                    if (r.type == DnsRecordType.A && !parent.supportsARecords() || r.type == DnsRecordType.AAAA && !parent.supportsAAAARecords()) {
                        continue
                    }
                    val recordName = r.name.toString()
                    val authoritativeNameServer = serverNames.remove(recordName) ?: // Not a server we are interested in.
                    continue
                    val resolved = parseAddress(r, recordName) ?: // Could not parse it, move to the next.
                    continue
                    nameServers.add(InetSocketAddress(resolved, parent.dnsRedirectPort(resolved)))
                    addNameServerToCache(authoritativeNameServer, resolved, r.ttl)
                }
                if (!nameServers.isEmpty()) {
                    resolveQuery(
                        parent.uncachedRedirectDnsServerStream(nameServers),
                        0,
                        question,
                        queryLifecycleObserver.queryRedirected(nameServers.toList()),
                        promise)
                    return true
                }
            }
        }
        return false
    }

    private fun onResponseAorAAAA(
        qType: Int, question: DnsMessage, response: DnsResponse, queryLifecycleObserver: DnsQueryLifecycleObserver, promise: Promise<T>
    ) {

        // We often get a bunch of CNAMES as well when we asked for A/AAAA.
        val cnames = buildAliasMap(response)
        val answerArray = response.getSectionArray(DnsSection.ANSWER)
        var found = false
        for (i in answerArray.indices) {
            val r = answerArray[i]
            val type = r.type
            if (type != DnsRecordType.A && type != DnsRecordType.AAAA) {
                continue
            }

            val questionName = question.question!!.name.toString()
            val recordName = r.name.toString()

            // Make sure the record is for the questioned domain.
            if (recordName != questionName) {
                // Even if the record's name is not exactly same, it might be an alias defined in the CNAME records.
                var resolved: String? = questionName
                do {
                    resolved = cnames[resolved]
                    if (recordName == resolved) {
                        break
                    }
                } while (resolved != null)
                if (resolved == null) {
                    continue
                }
            }
            val resolved = parseAddress(r, hostname) ?: continue
            if (resolvedEntries == null) {
                resolvedEntries = ArrayList(8)
            }
            val e = DnsCacheEntry(hostname, resolved)
            resolveCache.cache(hostname, resolved, r.ttl, parent.ch.eventLoop())
            resolvedEntries!!.add(e)
            found = true

            // Note that we do not break from the loop here, so we decode/cache all A/AAAA records.
        }
        if (found) {
            queryLifecycleObserver.querySucceed()
            return
        }
        if (cnames.isEmpty()) {
            queryLifecycleObserver.queryFailed(NO_MATCHING_RECORD_QUERY_FAILED_EXCEPTION)
        } else {
            // We asked for A/AAAA but we got only CNAME.
            onResponseCNAME(question, response, cnames, queryLifecycleObserver, promise)
        }
    }

    private fun parseAddress(record: DnsRecord, name: String): InetAddress? {
        val type = record.type
        return if (type == DnsRecordType.A) {
            val aRecord = record as ARecord
            aRecord.address
        } else if (type == DnsRecordType.AAAA) {
            val aaaaRecord = record as AAAARecord
            aaaaRecord.getAddress()
        } else {
            null
        }
    }

    private fun onResponseCNAME(
        question: DnsMessage, response: DnsResponse, queryLifecycleObserver: DnsQueryLifecycleObserver, promise: Promise<T>
    ) {
        onResponseCNAME(question, response, buildAliasMap(response), queryLifecycleObserver, promise)
    }

    private fun onResponseCNAME(
        question: DnsMessage,
        response: DnsResponse,
        cnames: MutableMap<String, String>,
        queryLifecycleObserver: DnsQueryLifecycleObserver,
        promise: Promise<T>
    ) {

        // Resolve the host name in the question into the real host name.
        var resolved = question.question!!.name.toString()
        var found = false
        while (cnames.isNotEmpty()) { // Do not attempt to call Map.remove() when the Map is empty
            // because it can be Collections.emptyMap()
            // whose remove() throws a UnsupportedOperationException.
            val next = cnames.remove(resolved)
            if (next != null) {
                found = true
                resolved = next
            } else {
                break
            }
        }
        if (found) {
            followCname(resolved, queryLifecycleObserver, promise)
        } else {
            queryLifecycleObserver.queryFailed(CNAME_NOT_FOUND_QUERY_FAILED_EXCEPTION)
        }
    }

    fun tryToFinishResolve(
        nameServerAddrStream: DnsServerAddressStream,
        nameServerAddrStreamIndex: Int,
        question: DnsQuestion,
        queryLifecycleObserver: DnsQueryLifecycleObserver,
        promise: Promise<T>
    ) {
        // There are no queries left to try.
        if (!queriesInProgress.isEmpty()) {
            queryLifecycleObserver.queryCancelled(allowedQueries)

            // There are still some queries we did not receive responses for.
            if (gotPreferredAddress()) {
                // But it's OK to finish the resolution process if we got a resolved address of the preferred type.
                finishResolve(promise, question)
            }

            // We did not get any resolved address of the preferred type, so we can't finish the resolution process.
            return
        }

        // There are no queries left to try.
        if (resolvedEntries == null) {
            if (nameServerAddrStreamIndex < nameServerAddrStream.size()) {
                // the query is going to use the question again...
                question.retain()
                if (queryLifecycleObserver === NoopDnsQueryLifecycleObserver.INSTANCE) {
                    // If the queryLifecycleObserver has already been terminated we should create a new one for this
                    // fresh query.
                    resolveQuery(nameServerAddrStream, nameServerAddrStreamIndex + 1, question, promise)
                } else {
                    resolveQuery(nameServerAddrStream, nameServerAddrStreamIndex + 1, question, queryLifecycleObserver, promise)
                }
                return
            }
            queryLifecycleObserver.queryFailed(NAME_SERVERS_EXHAUSTED_EXCEPTION)

            // .. and we could not find any A/AAAA records.
            if (!triedCNAME) {
                // As the last resort, try to query CNAME, just in case the name server has it.
                triedCNAME = true
                resolveQuery(hostname, DnsRecordType.CNAME, getNameServers(hostname), promise)
                return
            }
        } else {
            queryLifecycleObserver.queryCancelled(allowedQueries)
        }

        // We have at least one resolved address or tried CNAME as the last resort..
        finishResolve(promise, question)
    }

    private fun gotPreferredAddress(): Boolean {
        if (resolvedEntries == null) {
            return false
        }
        val size = resolvedEntries!!.size
        val inetAddressType = parent.preferredAddressType().addressType()
        for (i in 0 until size) {
            val address = resolvedEntries!![i].address()
            if (inetAddressType.isInstance(address)) {
                return true
            }
        }
        return false
    }

    private fun finishResolve(promise: Promise<T>, question: DnsQuestion) {
        // now we are done with the question.
        question.release()
        if (!queriesInProgress.isEmpty()) {
            // If there are queries in progress, we should cancel it because we already finished the resolution.
            val i = queriesInProgress.iterator()
            while (i.hasNext()) {
                val f = i.next()
                i.remove()
                if (!f.cancel(false)) {
                    f.addListener(RELEASE_RESPONSE)
                }
            }
        }
        if (resolvedEntries != null) {
            // Found at least one resolved address.
            for (f in resolvedInternetProtocolFamilies) {
                if (finishResolve(f.addressType(), resolvedEntries!!, promise)) {
                    return
                }
            }
        }

        // No resolved address found.
        val tries = maxAllowedQueries - allowedQueries
        val buf = StringBuilder(64)
        buf.append("failed to resolve '").append(hostname).append('\'')
        if (tries > 1) {
            if (tries < maxAllowedQueries) {
                buf.append(" after ").append(tries).append(" queries ")
            } else {
                buf.append(". Exceeded max queries per resolve ").append(maxAllowedQueries).append(' ')
            }
        }
        val cause = UnknownHostException(buf.toString())
        cause.stackTrace = arrayOfNulls(0)
        resolveCache.cache(hostname, cause, parent.ch.eventLoop())
        promise.tryFailure(cause)
    }

    abstract fun finishResolve(addressType: Class<out InetAddress>, resolvedEntries: List<DnsCacheEntry>, promise: Promise<T>): Boolean

    abstract fun newResolverContext(
        parent: DnsNameResolver, hostname: String, resolveCache: DnsCache, nameServerAddrs: DnsServerAddressStream
    ): DnsNameResolverContext<T>

    private fun getNameServers(hostname: String): DnsServerAddressStream {
        val stream = getNameServersFromCache(hostname)
        return stream ?: nameServerAddrs
    }

    private fun followCname(cname: String, queryLifecycleObserver: DnsQueryLifecycleObserver, promise: Promise<T>) {

        // Use the same server for both CNAME queries
        val stream = DnsServerAddresses.singleton(getNameServers(cname).next()).stream()
        var cnameQuestion: DnsQuestion? = null
        try {
            if (parent.supportsARecords()) {
                cnameQuestion = newResolveQuestion(hostname, DnsRecordType.A, parent.isRecursionDesired)
            }
            if (parent.supportsAAAARecords()) {
                cnameQuestion = newResolveQuestion(hostname, DnsRecordType.AAAA, parent.isRecursionDesired)
            }
        } catch (cause: Throwable) {
            queryLifecycleObserver.queryFailed(cause)
            PlatformDependent.throwException(cause)
        }
        if (cnameQuestion != null) {
            resolveQuery(stream, 0, cnameQuestion, queryLifecycleObserver.queryCNAMEd(cnameQuestion), promise)
        }
    }

    private fun resolveQuery(hostname: String, type: Int, dnsServerAddressStream: DnsServerAddressStream, promise: Promise<T>): Boolean {
        val message = newResolveQuestion(hostname, type, parent.isRecursionDesired) ?: return false
        resolveQuery(dnsServerAddressStream, 0, message, promise)
        return true
    }

    /**
     * Holds the closed DNS Servers for a domain.
     */
    private class AuthoritativeNameServerList internal constructor(questionName: String) {
        private val questionName: String

        // We not expect the linked-list to be very long so a double-linked-list is overkill.
        private var head: AuthoritativeNameServer? = null
        private var count = 0

        init {
            this.questionName = questionName.lowercase()
        }

        fun add(record: DnsRecord) {
            if (record.type != DnsRecordType.NS) {
                return
            }

            // Only include servers that serve the correct domain.
            val recordName = record.name.toString()
            if (questionName.length < recordName.length) {
                return
            }
            var dots = 0
            var a = recordName.length - 1
            var b = questionName.length - 1
            while (a >= 0) {
                val c = recordName[a]
                if (questionName[b] != c) {
                    return
                }
                if (c == '.') {
                    dots++
                }
                a--
                b--
            }
            if (head != null && head!!.dots > dots) {
                // We already have a closer match so ignore this one, no need to parse the domainName etc.
                return
            }
            System.err.println("DOUBLE CHECK me! we do things differently now!")
            val re = record as NSRecord
            val domainName = re.additionalName.toString() ?: // Could not be parsed, ignore.
            return

            // We are only interested in preserving the nameservers which are the closest to our qName, so ensure
            // we drop servers that have a smaller dots count.
            if (head == null || head!!.dots < dots) {
                count = 1
                head = AuthoritativeNameServer(dots, recordName, domainName)
            } else if (head!!.dots == dots) {
                var serverName = head
                while (serverName!!.next != null) {
                    serverName = serverName.next
                }
                serverName.next = AuthoritativeNameServer(dots, recordName, domainName)
                count++
            }
        }

        // Just walk the linked-list and mark the entry as removed when matched, so next lookup will need to process
        // one node less.
        fun remove(nsName: String?): AuthoritativeNameServer? {
            var serverName = head
            while (serverName != null) {
                if (!serverName.removed && serverName.nsName.equals(nsName, ignoreCase = true)) {
                    serverName.removed = true
                    return serverName
                }
                serverName = serverName.next
            }
            return null
        }

        fun size(): Int {
            return count
        }
    }

    internal class AuthoritativeNameServer(val dots: Int, val domainName: String, val nsName: String) {
        var next: AuthoritativeNameServer? = null
        var removed = false

        /**
         * Returns `true` if its a root server.
         */
        val isRootServer: Boolean
            get() = dots == 1

        /**
         * The domain for which the [AuthoritativeNameServer] is responsible.
         */
        fun domainName(): String {
            return domainName
        }
    }

    companion object {
        private val RELEASE_RESPONSE: FutureListener<DnsResponse> = object : FutureListener<DnsResponse> {
            override fun operationComplete(future: Future<DnsResponse>) {
                if (future.isSuccess) {
                    future.now.release()
                }
            }
        }
        private val NXDOMAIN_QUERY_FAILED_EXCEPTION = ThrowableUtil.unknownStackTrace(
            RuntimeException("No answer found and NXDOMAIN response code returned"), DnsNameResolverContext::class.java, "onResponse(..)"
        )
        private val CNAME_NOT_FOUND_QUERY_FAILED_EXCEPTION = ThrowableUtil.unknownStackTrace(
            RuntimeException("No matching CNAME record found"), DnsNameResolverContext::class.java, "onResponseCNAME(..)"
        )
        private val NO_MATCHING_RECORD_QUERY_FAILED_EXCEPTION = ThrowableUtil.unknownStackTrace(
            RuntimeException("No matching record type found"), DnsNameResolverContext::class.java, "onResponseAorAAAA(..)"
        )
        private val UNRECOGNIZED_TYPE_QUERY_FAILED_EXCEPTION = ThrowableUtil.unknownStackTrace(
            RuntimeException("Response type was unrecognized"), DnsNameResolverContext::class.java, "onResponse(..)"
        )
        private val NAME_SERVERS_EXHAUSTED_EXCEPTION = ThrowableUtil.unknownStackTrace(
            RuntimeException("No name servers returned an answer"), DnsNameResolverContext::class.java, "tryToFinishResolve(..)"
        )

        /**
         * Returns the `{ AuthoritativeNameServerList} which were included in { DnsSection#AUTHORITY}
         * or { null} if non are found.`
         */
        private fun extractAuthoritativeNameServers(questionName: String, res: DnsResponse): AuthoritativeNameServerList? {
            val authority = res.getSectionArray(DnsSection.AUTHORITY)
            if (authority.size == 0) {
                return null
            }
            System.err.println("TYODO")
            val serverNames = AuthoritativeNameServerList(questionName)
            for (i in authority.indices) {
                val dnsRecord = authority[i]
                serverNames.add(dnsRecord)
            }
            return serverNames
        }

        private fun buildAliasMap(response: DnsMessage): MutableMap<String, String> {
            val answerArray = response.getSectionArray(DnsSection.ANSWER)
            var cnames: MutableMap<String, String>? = null
            val length = answerArray.size
            for (i in 0 until length) {
                val record = answerArray[i]
                val type = record.type
                if (type != DnsRecordType.CNAME) {
                    continue
                }
                System.err.println("CHECK ME ME! we don't have bytebuf content in this fashion anymore")
                val re = record as CNAMERecord
                val domainName = re.alias.toString() ?: continue
                if (cnames == null) {
                    cnames = HashMap(Math.min(8, length))
                }
                cnames[record.name.toString().lowercase()] = domainName.lowercase()
            }
            return cnames ?: mutableMapOf()
        }
    }
}
