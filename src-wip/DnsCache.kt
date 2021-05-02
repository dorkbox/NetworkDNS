//package dorkbox.network
//
//import dorkbox.netUtil.IPv4
//import dorkbox.util.collections.IntMap
//
///*
// * This is a "most complex" example of how DNS entries can be used.
// * NOTE: D can have B (domain) as a parent AND ALSO 1 (ip) as a parent.
// *
// *  ROOT:     1   2    3
// *           /|\ /|    |
// *          / | X |    |
// *         |  |/ \|    |
// * CHILD:  |  A   B    C
// *         |     /|\
// *          \   / | \
// *           \ /  |  \
// * CHILD:     D   E   F
// */
//internal class DnsCache {
//    internal open inner class Entry {
//        var children: MutableMap<String?, DomainEntry?>? = HashMap()
//    }
//
//    internal inner class IpEntry : Entry() {
//        var ip = 0
//        val ipAsString: String
//            get() = IPv4.toString(ip)
//    }
//
//    internal inner class DomainEntry : Entry() {
//        var domain: String? = null
//
//        // we can have BOTH parent IPs and parent DOMAINS
//        var parentIPs: IntMap<IpEntry> = IntMap()
//        var parentDomains: MutableMap<String, DomainEntry> = HashMap()
//    }
//
//    // this map contains ALL of the DOMAIN'S possible (then, each domain has 1+ parents or 1+ children
//    private val domains: MutableMap<String, DomainEntry> = HashMap()
//
//    // this map contains ALL of the IP'S possible (then, each IP will have 1+ children)
//    private val ips: IntMap<IpEntry> = IntMap()
//
//
//    private fun getDomain(domain: String): DomainEntry? {
//        var domainEntry = domains[domain]
//        if (domainEntry == null) {
//            domainEntry = DomainEntry()
//            domainEntry.domain = domain
//            domains[domain] = domainEntry
//        }
//        return domainEntry
//    }
//
//    private fun linkParentAndChild(parentDomain: String, childEntry: DomainEntry) {
//        var parentEntry = domains[parentDomain]
//        if (parentEntry == null) {
//            parentEntry = DomainEntry()
//            parentEntry.domain = parentDomain
//            domains[parentDomain] = parentEntry
//        }
//
//        // link the two together
//        childEntry.parentDomains[parentDomain] = parentEntry
//        parentEntry.children!![childEntry.domain] = childEntry
//    }
//
//    private fun linkParentAndChild(parentIp: Int, childEntry: DomainEntry?) {
//        var parentEntry: IpEntry = ips.get(parentIp)
//        if (parentEntry == null) {
//            parentEntry = IpEntry()
//            parentEntry.ip = parentIp
//            ips.put(parentIp, parentEntry)
//        }
//
//        // link the two together
//        childEntry!!.parentIPs.put(parentIp, parentEntry)
//        parentEntry.children!![childEntry.domain] = childEntry
//    }
//
//    // also, one question can have multiple answers, and we don't want to overwrite them if the same IP goes to multiple questions.
//    //
//    // As "criss-crossy" and weird as this CAN get, we reset this at midnight, JUST because this will get crazy. As a result, we do not do
//    // any maintenance on the map. It is not TOO likely that IPs will change in 1 day. It is definitely possible, and this solves the
//    // problem by just "hanging onto" the old IPs for the rest of the day.  Since we rewrite the TTL on DNS packets to be 60 seconds, it
//    // should also prevent stale lookups
////    fun processDNS(dns: dnsEntry) {
////        // here we have to correlate CNAME with original question, because the QUESTION is what we know and care about
////        val question: String = dns.question
////        if (question != null) {
////            val childEntry = getDomain(question)
////            for (cName in dns.cname) {
////                // the cName will be the parent to the question
////                linkParentAndChild(cName, childEntry)
////            }
////            for (aRecord in dns.a) {
////                val asInt = toInt(aRecord!!)
////
////                // can ONLY be a parent to our question
////                linkParentAndChild(asInt, childEntry)
////            }
////        }
////        else {
////            // this makes GC graph traversal faster
////            for (domainEntry in domains!!.values) {
////                domainEntry!!.parentIPs.clear()
////                domainEntry.parentDomains!!.clear()
////                domainEntry.children!!.clear()
////            }
////            domains.clear()
////
////            // this makes GC graph traversal faster
////            for (o in ips.values()) {
////                val ipEntry = o as IpEntry
////                ipEntry.children!!.clear()
////            }
////            ips.clear()
////
////            // encourage GC, since a heck of a lot of entries just got nuked.
////            System.gc()
////        }
////    }
//
//    /**
//     * quite often, the domain for traffic is **really** the CNAME value for the original DNS question
//     *
//     * @param dnsDomain the domain to check (to see if it maps to an original DNS question)
//     *
//     * @return either the original question DNS value, or dnsDomain.
//     */
//    operator fun get(dnsDomain: String?): String? {
////        HashSet<String> dns = reverseMap.get(dnsDomain);
////        if (dns == null) {
////            return dnsDomain;
////        }
////        else {
////            // WORST CASE SITUATION
////            // have to keep on going, because at some point A->B->C
////            // 1.2.3.4 -> foo.akamai.net -> cdn.turner.com -> cnn.com
////            // 5.6.7.8 -> foo.akamai.net -> cdn.turner.com -> cnn.com
////            // 5.6.7.8 -> foo.akamai.net -> espn.com
////            // 1.2.7.8 -> foo.akamai.net -> bmw.com
////            // 1.2.7.8 -> bar.akamai.net -> ford.com
////
//////            HashSet<String> strings = get(dns);
//////            if (strings.size() == 1) {
//////            }
////            return dnsDomain;
////        }
//        return ""
//    }
//}
