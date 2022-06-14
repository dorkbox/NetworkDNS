/*
 * Copyright 2013 dorkbox, llc
 *
 * Copyright (C) 2016 Tres Finocchiaro, QZ Industries, LLC
 * Derivative code has been released as Apache 2.0, used with permission.
 *
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
package dorkbox.dns

import java.util.concurrent.*

/**
 * And the effective_tld_names.dat is from mozilla (the following are all the same data)
 *
 *
 * https://mxr.mozilla.org/mozilla-central/source/netwerk/dns/effective_tld_names.dat?raw=1
 * which is...
 * https://publicsuffix.org/list/effective_tld_names.dat
 *
 *
 * also
 *
 *
 * https://publicsuffix.org/list/public_suffix_list.dat
 */
object DNS {
    private val exceptions = HashSet<String>()
    private val suffixes = HashSet<String>()

    fun init() {
        // just here to load the class.
    }

    private fun createLocalDomainMap(): Map<String?, Boolean?>? {
        val map: ConcurrentHashMap<String?, Boolean?> = ConcurrentHashMap()
        map.put(".localhost.", java.lang.Boolean.TRUE) // RFC 6761
        map.put(".test.", java.lang.Boolean.TRUE) // RFC 6761
        map.put(".local.", java.lang.Boolean.TRUE) // RFC 6762
        map.put(".local", java.lang.Boolean.TRUE)
        map.put(".localdomain", java.lang.Boolean.TRUE)
        return map
    }

    init {
        /*
         * Parses the list from publicsuffix.org
         * new one at:
         * http://svn.apache.org/repos/asf/httpcomponents/httpclient/trunk/httpclient5/src/main/java/org/apache/hc/client5/http/impl/cookie/PublicSuffixDomainFilter.java
         * and
         * http://svn.apache.org/repos/asf/httpcomponents/httpclient/trunk/httpclient5/src/main/java/org/apache/hc/client5/http/psl/
         */

        // now load this file into memory, so it's faster to process.
        val tldResource = DNS.javaClass.getResourceAsStream("/effective_tld_names.dat")
        tldResource.bufferedReader().useLines { lines ->
            lines.forEach { line ->
                var line = line

                // entire lines can also be commented using //
                if (line.isNotEmpty() && !line.startsWith("//")) {

                    if (line.startsWith(".")) {
                        line = line.substring(1) // A leading dot is optional
                    }

                    // An exclamation mark (!) at the start of a rule marks an exception
                    // to a previous wildcard rule
                    val isException = line.startsWith("!")
                    if (isException) {
                        line = line.substring(1)
                    }

                    if (isException) {
                        exceptions.add(line)
                    } else {
                        suffixes.add(line)
                    }
                }
            }
        }
    }

    /**
     * Extracts the second level domain, from a fully qualified domain (ie: www.aa.com, or www.amazon.co.uk).
     *
     *
     * This algorithm works from left to right parsing the domain string parameter
     *
     * @param domain a fully qualified domain (ie: www.aa.com, or www.amazon.co.uk)
     *
     * @return null (if there is no second level domain) or the SLD www.aa.com -> aa.com , or www.amazon.co.uk -> amazon.co.uk
     */
    fun extractSLD(domain: String): String? {
        var domain = domain
        var last = domain
        var anySLD = false

        do {
            if (isTLD(domain)) {
                return if (anySLD) {
                    last
                }
                else {
                    null
                }
            }

            anySLD = true
            last = domain

            val nextDot = domain.indexOf(".")
            if (nextDot == -1) {
                return null
            }

            domain = domain.substring(nextDot + 1)
        } while (domain.isNotEmpty())

        return null
    }

    /**
     * Returns a domain that is without its TLD at the end.
     *
     * @param domain  domain a fully qualified domain or not, (ie: www.aa.com, or amazon.co.uk).
     *
     * @return a domain that is without it's TLD, ie: www.aa.com -> www.aa, or google.com -> google
     */
    fun withoutTLD(domain: String): String {
        var index = 0
        while (index != -1) {
            index = domain.indexOf('.', index)

            if (index != -1) {
                if (isTLD(domain.substring(index))) {
                    return domain.substring(0, index)
                }
                index++
            }
            else {
                return ""
            }
        }

        return ""
    }

    /**
     * Checks if the domain is a TLD.
     */
    fun isTLD(domain: String): Boolean {
        var domain = domain
        if (domain.startsWith(".")) {
            domain = domain.substring(1)
        }

        // An exception rule takes priority over any other matching rule.
        // Exceptions are ones that are not a TLD, but would match a pattern rule
        // e.g. bl.uk is not a TLD, but the rule *.uk means it is. Hence there is an exception rule
        // stating that bl.uk is not a TLD.
        if (exceptions.contains(domain)) {
            return false
        }

        if (suffixes.contains(domain)) {
            return true
        }

        // Try patterns. ie *.jp means that boo.jp is a TLD
        val nextdot = domain.indexOf('.')
        if (nextdot == -1) {
            return false
        }
        domain = "*" + domain.substring(nextdot)

        return suffixes.contains(domain)
    }
}
