// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS2.resolver;

import java.io.IOException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.xbill.DNS2.clients.Master;

import dorkbox.network.dns.Name;
import dorkbox.network.dns.constants.DnsClass;
import dorkbox.network.dns.constants.DnsRecordType;
import dorkbox.network.dns.constants.DnsResponseCode;
import dorkbox.network.dns.constants.DnsSection;
import dorkbox.network.dns.constants.Flags;
import dorkbox.network.dns.exceptions.NameTooLongException;
import dorkbox.network.dns.records.CNAMERecord;
import dorkbox.network.dns.records.DNAMERecord;
import dorkbox.network.dns.records.DnsMessage;
import dorkbox.network.dns.records.DnsRecord;
import dorkbox.network.dns.records.RRset;
import dorkbox.network.dns.records.SOARecord;
import dorkbox.network.dns.utils.Options;

/**
 * A cache of DNS records.  The cache obeys TTLs, so items are purged after
 * their validity period is complete.  Negative answers are cached, to
 * avoid repeated failed DNS queries.  The credibility of each RRset is
 * maintained, so that more credible records replace less credible records,
 * and lookups can specify the minimum credibility of data they are requesting.
 *
 * @author Brian Wellington
 * @see RRset
 * @see Credibility
 */

public
class Cache {

    private CacheMap data;
    private int maxncache = -1;
    private int maxcache = -1;
    private int dclass;
    private static final int defaultMaxEntries = 50000;


    private
    interface Element {
        public
        boolean expired();

        public
        int compareCredibility(int cred);

        public
        int getType();
    }

    private static
    int limitExpire(long ttl, long maxttl) {
        if (maxttl >= 0 && maxttl < ttl) {
            ttl = maxttl;
        }
        long expire = (System.currentTimeMillis() / 1000) + ttl;
        if (expire < 0 || expire > Integer.MAX_VALUE) {
            return Integer.MAX_VALUE;
        }
        return (int) expire;
    }


    private static
    class CacheRRset extends RRset implements Element {
        private static final long serialVersionUID = 5971755205903597024L;

        int credibility;
        int expire;

        public
        CacheRRset(DnsRecord rec, int cred, long maxttl) {
            super();
            this.credibility = cred;
            this.expire = limitExpire(rec.getTTL(), maxttl);
            addRR(rec);
        }

        public
        CacheRRset(RRset rrset, int cred, long maxttl) {
            super(rrset);
            this.credibility = cred;
            this.expire = limitExpire(rrset.getTTL(), maxttl);
        }

        @Override
        public final
        boolean expired() {
            int now = (int) (System.currentTimeMillis() / 1000);
            return (now >= expire);
        }

        public
        String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(super.toString());
            sb.append(" cl = ");
            sb.append(credibility);
            return sb.toString();
        }        @Override
        public final
        int compareCredibility(int cred) {
            return credibility - cred;
        }


    }


    private static
    class NegativeElement implements Element {
        int type;
        Name name;
        int credibility;
        int expire;

        public
        NegativeElement(Name name, int type, SOARecord soa, int cred, long maxttl) {
            this.name = name;
            this.type = type;
            long cttl = 0;
            if (soa != null) {
                cttl = soa.getMinimum();
            }
            this.credibility = cred;
            this.expire = limitExpire(cttl, maxttl);
        }

        public
        String toString() {
            StringBuilder sb = new StringBuilder();
            if (type == 0) {
                sb.append("NXDOMAIN ")
                  .append(name);
            }
            else {
                sb.append("NXRRSET ")
                  .append(name)
                  .append(" ")
                  .append(DnsRecordType.string(type));
            }
            sb.append(" cl = ");
            sb.append(credibility);
            return sb.toString();
        }

        @Override
        public
        int getType() {
            return type;
        }

        @Override
        public final
        boolean expired() {
            int now = (int) (System.currentTimeMillis() / 1000);
            return (now >= expire);
        }

        @Override
        public final
        int compareCredibility(int cred) {
            return credibility - cred;
        }


    }


    private static
    class CacheMap extends LinkedHashMap {
        private int maxsize = -1;

        CacheMap(int maxsize) {
            super(16, (float) 0.75, true);
            this.maxsize = maxsize;
        }

        int getMaxSize() {
            return maxsize;
        }

        void setMaxSize(int maxsize) {
        /*
		 * Note that this doesn't shrink the size of the map if
		 * the maximum size is lowered, but it should shrink as
		 * entries expire.
		 */
            this.maxsize = maxsize;
        }

        @Override
        protected
        boolean removeEldestEntry(Map.Entry eldest) {
            return maxsize >= 0 && size() > maxsize;
        }
    }

    /**
     * Creates an empty Cache for class IN.
     *
     * @see DnsClass
     */
    public
    Cache() {
        this(DnsClass.IN);
    }

    /**
     * Creates an empty Cache
     *
     * @param dclass The DNS class of this cache
     *
     * @see DnsClass
     */
    public
    Cache(int dclass) {
        this.dclass = dclass;
        data = new CacheMap(defaultMaxEntries);
    }

    /**
     * Creates a Cache which initially contains all records in the specified file.
     */
    public
    Cache(String file) throws IOException {
        data = new CacheMap(defaultMaxEntries);
        Master m = new Master(file);
        DnsRecord record;
        while ((record = m.nextRecord()) != null) {
            addRecord(record, Credibility.HINT, m);
        }
    }

    private synchronized
    Object exactName(Name name) {
        return data.get(name);
    }

    private synchronized
    Element findElement(Name name, int type, int minCred) {
        Object types = exactName(name);
        if (types == null) {
            return null;
        }
        return oneElement(name, types, type, minCred);
    }

    private synchronized
    void addElement(Name name, Element element) {
        Object types = data.get(name);
        if (types == null) {
            data.put(name, element);
            return;
        }
        int type = element.getType();
        if (types instanceof List) {
            List list = (List) types;
            for (int i = 0; i < list.size(); i++) {
                Element elt = (Element) list.get(i);
                if (elt.getType() == type) {
                    list.set(i, element);
                    return;
                }
            }
            list.add(element);
        }
        else {
            Element elt = (Element) types;
            if (elt.getType() == type) {
                data.put(name, element);
            }
            else {
                LinkedList list = new LinkedList();
                list.add(elt);
                list.add(element);
                data.put(name, list);
            }
        }
    }

    /**
     * Empties the Cache.
     */
    public synchronized
    void clearCache() {
        data.clear();
    }

    /**
     * Adds a record to the Cache.
     *
     * @param r The record to be added
     * @param cred The credibility of the record
     * @param o The source of the record (this could be a DnsMessage, for example)
     *
     * @see DnsRecord
     */
    public synchronized
    void addRecord(DnsRecord r, int cred, Object o) {
        Name name = r.getName();
        int type = r.getRRsetType();
        if (!DnsRecordType.isRR(type)) {
            return;
        }
        Element element = findElement(name, type, cred);
        if (element == null) {
            CacheRRset crrset = new CacheRRset(r, cred, maxcache);
            addRRset(crrset, cred);
        }
        else if (element.compareCredibility(cred) == 0) {
            if (element instanceof CacheRRset) {
                CacheRRset crrset = (CacheRRset) element;
                crrset.addRR(r);
            }
        }
    }

    /**
     * Adds an RRset to the Cache.
     *
     * @param rrset The RRset to be added
     * @param cred The credibility of these records
     *
     * @see RRset
     */
    public synchronized
    void addRRset(RRset rrset, int cred) {
        long ttl = rrset.getTTL();
        Name name = rrset.getName();
        int type = rrset.getType();
        Element element = findElement(name, type, 0);
        if (ttl == 0) {
            if (element != null && element.compareCredibility(cred) <= 0) {
                removeElement(name, type);
            }
        }
        else {
            if (element != null && element.compareCredibility(cred) <= 0) {
                element = null;
            }
            if (element == null) {
                CacheRRset crrset;
                if (rrset instanceof CacheRRset) {
                    crrset = (CacheRRset) rrset;
                }
                else {
                    crrset = new CacheRRset(rrset, cred, maxcache);
                }
                addElement(name, crrset);
            }
        }
    }

    /**
     * Adds a negative entry to the Cache.
     *
     * @param name The name of the negative entry
     * @param type The type of the negative entry
     * @param soa The SOA record to add to the negative cache entry, or null.
     *         The negative cache ttl is derived from the SOA.
     * @param cred The credibility of the negative entry
     */
    public synchronized
    void addNegative(Name name, int type, SOARecord soa, int cred) {
        long ttl = 0;
        if (soa != null) {
            ttl = soa.getTTL();
        }
        Element element = findElement(name, type, 0);
        if (ttl == 0) {
            if (element != null && element.compareCredibility(cred) <= 0) {
                removeElement(name, type);
            }
        }
        else {
            if (element != null && element.compareCredibility(cred) <= 0) {
                element = null;
            }
            if (element == null) {
                addElement(name, new NegativeElement(name, type, soa, cred, maxncache));
            }
        }
    }

    /**
     * Looks up credible Records in the Cache (a wrapper around lookupRecords).
     * Unlike lookupRecords, this given no indication of why failure occurred.
     *
     * @param name The name to look up
     * @param type The type to look up
     *
     * @return An array of RRsets, or null
     *
     * @see Credibility
     */
    public
    RRset[] findRecords(Name name, int type) {
        return findRecords(name, type, Credibility.NORMAL);
    }

    private
    RRset[] findRecords(Name name, int type, int minCred) {
        SetResponse cr = lookupRecords(name, type, minCred);
        if (cr.isSuccessful()) {
            return cr.answers();
        }
        else {
            return null;
        }
    }

    /**
     * Looks up Records in the Cache.  This follows CNAMEs and handles negatively
     * cached data.
     *
     * @param name The name to look up
     * @param type The type to look up
     * @param minCred The minimum acceptable credibility
     *
     * @return A SetResponse object
     *
     * @see SetResponse
     * @see Credibility
     */
    public
    SetResponse lookupRecords(Name name, int type, int minCred) {
        return lookup(name, type, minCred);
    }

    /**
     * Finds all matching sets or something that causes the lookup to stop.
     */
    protected synchronized
    SetResponse lookup(Name name, int type, int minCred) {
        int labels;
        int tlabels;
        Element element;
        Name tname;
        Object types;
        SetResponse sr;

        labels = name.labels();

        for (tlabels = labels; tlabels >= 1; tlabels--) {
            boolean isRoot = (tlabels == 1);
            boolean isExact = (tlabels == labels);

            if (isRoot) {
                tname = Name.root;
            }
            else if (isExact) {
                tname = name;
            }
            else {
                tname = new Name(name, labels - tlabels);
            }

            types = data.get(tname);
            if (types == null) {
                continue;
            }

		/*
		 * If this is the name, look for the actual type or a CNAME
		 * (unless it's an ANY query, where we return everything).
		 * Otherwise, look for a DNAME.
		 */
            if (isExact && type == DnsRecordType.ANY) {
                sr = new SetResponse(SetResponse.SUCCESSFUL);
                Element[] elements = allElements(types);
                int added = 0;
                for (int i = 0; i < elements.length; i++) {
                    element = elements[i];
                    if (element.expired()) {
                        removeElement(tname, element.getType());
                        continue;
                    }
                    if (!(element instanceof CacheRRset)) {
                        continue;
                    }
                    if (element.compareCredibility(minCred) < 0) {
                        continue;
                    }
                    sr.addRRset((CacheRRset) element);
                    added++;
                }
			/* There were positive entries */
                if (added > 0) {
                    return sr;
                }
            }
            else if (isExact) {
                element = oneElement(tname, types, type, minCred);
                if (element != null && element instanceof CacheRRset) {
                    sr = new SetResponse(SetResponse.SUCCESSFUL);
                    sr.addRRset((CacheRRset) element);
                    return sr;
                }
                else if (element != null) {
                    sr = new SetResponse(SetResponse.NXRRSET);
                    return sr;
                }

                element = oneElement(tname, types, DnsRecordType.CNAME, minCred);
                if (element != null && element instanceof CacheRRset) {
                    return new SetResponse(SetResponse.CNAME, (CacheRRset) element);
                }
            }
            else {
                element = oneElement(tname, types, DnsRecordType.DNAME, minCred);
                if (element != null && element instanceof CacheRRset) {
                    return new SetResponse(SetResponse.DNAME, (CacheRRset) element);
                }
            }

		/* Look for an NS */
            element = oneElement(tname, types, DnsRecordType.NS, minCred);
            if (element != null && element instanceof CacheRRset) {
                return new SetResponse(SetResponse.DELEGATION, (CacheRRset) element);
            }

		/* Check for the special NXDOMAIN element. */
            if (isExact) {
                element = oneElement(tname, types, 0, minCred);
                if (element != null) {
                    return SetResponse.ofType(SetResponse.NXDOMAIN);
                }
            }

        }
        return SetResponse.ofType(SetResponse.UNKNOWN);
    }

    private synchronized
    Element[] allElements(Object types) {
        if (types instanceof List) {
            List typelist = (List) types;
            int size = typelist.size();
            return (Element[]) typelist.toArray(new Element[size]);
        }
        else {
            Element set = (Element) types;
            return new Element[] {set};
        }
    }

    private synchronized
    Element oneElement(Name name, Object types, int type, int minCred) {
        Element found = null;

        if (type == DnsRecordType.ANY) {
            throw new IllegalArgumentException("oneElement(ANY)");
        }
        if (types instanceof List) {
            List list = (List) types;
            for (int i = 0; i < list.size(); i++) {
                Element set = (Element) list.get(i);
                if (set.getType() == type) {
                    found = set;
                    break;
                }
            }
        }
        else {
            Element set = (Element) types;
            if (set.getType() == type) {
                found = set;
            }
        }
        if (found == null) {
            return null;
        }
        if (found.expired()) {
            removeElement(name, type);
            return null;
        }
        if (found.compareCredibility(minCred) < 0) {
            return null;
        }
        return found;
    }

    private synchronized
    void removeElement(Name name, int type) {
        Object types = data.get(name);
        if (types == null) {
            return;
        }
        if (types instanceof List) {
            List list = (List) types;
            for (int i = 0; i < list.size(); i++) {
                Element elt = (Element) list.get(i);
                if (elt.getType() == type) {
                    list.remove(i);
                    if (list.size() == 0) {
                        data.remove(name);
                    }
                    return;
                }
            }
        }
        else {
            Element elt = (Element) types;
            if (elt.getType() != type) {
                return;
            }
            data.remove(name);
        }
    }

    /**
     * Looks up Records in the Cache (a wrapper around lookupRecords).  Unlike
     * lookupRecords, this given no indication of why failure occurred.
     *
     * @param name The name to look up
     * @param type The type to look up
     *
     * @return An array of RRsets, or null
     *
     * @see Credibility
     */
    public
    RRset[] findAnyRecords(Name name, int type) {
        return findRecords(name, type, Credibility.GLUE);
    }

    private
    int getCred(int section, boolean isAuth) {
        if (section == DnsSection.ANSWER) {
            if (isAuth) {
                return Credibility.AUTH_ANSWER;
            }
            else {
                return Credibility.NONAUTH_ANSWER;
            }
        }
        else if (section == DnsSection.AUTHORITY) {
            if (isAuth) {
                return Credibility.AUTH_AUTHORITY;
            }
            else {
                return Credibility.NONAUTH_AUTHORITY;
            }
        }
        else if (section == DnsSection.ADDITIONAL) {
            return Credibility.ADDITIONAL;
        }
        else {
            throw new IllegalArgumentException("getCred: invalid section");
        }
    }

    private static
    void markAdditional(RRset rrset, Set names) {
        DnsRecord first = rrset.first();
        if (first.getAdditionalName() == null) {
            return;
        }

        Iterator it = rrset.rrs();
        while (it.hasNext()) {
            DnsRecord r = (DnsRecord) it.next();
            Name name = r.getAdditionalName();
            if (name != null) {
                names.add(name);
            }
        }
    }

    /**
     * Adds all data from a DnsMessage into the Cache.  Each record is added with
     * the appropriate credibility, and negative answers are cached as such.
     *
     * @param in The DnsMessage to be added
     *
     * @return A SetResponse that reflects what would be returned from a cache
     *         lookup, or null if nothing useful could be cached from the message.
     *
     * @see DnsMessage
     */
    public
    SetResponse addMessage(DnsMessage in) {
        boolean isAuth = in.getHeader()
                           .getFlag(Flags.AA);
        DnsRecord question = in.getQuestion();
        Name qname;
        Name curname;
        int qtype;
        int qclass;
        int cred;
        int rcode = in.getHeader()
                      .getRcode();
        boolean completed = false;
        RRset[] answers, auth, addl;
        SetResponse response = null;
        boolean verbose = Options.check("verbosecache");
        HashSet additionalNames;

        if ((rcode != DnsResponseCode.NOERROR && rcode != DnsResponseCode.NXDOMAIN) || question == null) {
            return null;
        }

        qname = question.getName();
        qtype = question.getType();
        qclass = question.getDClass();

        curname = qname;

        additionalNames = new HashSet();

        answers = in.getSectionRRsets(DnsSection.ANSWER);
        for (int i = 0; i < answers.length; i++) {
            if (answers[i].getDClass() != qclass) {
                continue;
            }
            int type = answers[i].getType();
            Name name = answers[i].getName();
            cred = getCred(DnsSection.ANSWER, isAuth);
            if ((type == qtype || qtype == DnsRecordType.ANY) && name.equals(curname)) {
                addRRset(answers[i], cred);
                completed = true;
                if (curname == qname) {
                    if (response == null) {
                        response = new SetResponse(SetResponse.SUCCESSFUL);
                    }
                    response.addRRset(answers[i]);
                }
                markAdditional(answers[i], additionalNames);
            }
            else if (type == DnsRecordType.CNAME && name.equals(curname)) {
                CNAMERecord cname;
                addRRset(answers[i], cred);
                if (curname == qname) {
                    response = new SetResponse(SetResponse.CNAME, answers[i]);
                }
                cname = (CNAMERecord) answers[i].first();
                curname = cname.getTarget();
            }
            else if (type == DnsRecordType.DNAME && curname.subdomain(name)) {
                DNAMERecord dname;
                addRRset(answers[i], cred);
                if (curname == qname) {
                    response = new SetResponse(SetResponse.DNAME, answers[i]);
                }
                dname = (DNAMERecord) answers[i].first();
                try {
                    curname = curname.fromDNAME(dname);
                } catch (NameTooLongException e) {
                    break;
                }
            }
        }

        auth = in.getSectionRRsets(DnsSection.AUTHORITY);
        RRset soa = null, ns = null;
        for (int i = 0; i < auth.length; i++) {
            if (auth[i].getType() == DnsRecordType.SOA && curname.subdomain(auth[i].getName())) {
                soa = auth[i];
            }
            else if (auth[i].getType() == DnsRecordType.NS && curname.subdomain(auth[i].getName())) {
                ns = auth[i];
            }
        }
        if (!completed) {
		/* This is a negative response or a referral. */
            int cachetype = (rcode == DnsResponseCode.NXDOMAIN) ? 0 : qtype;
            if (rcode == DnsResponseCode.NXDOMAIN || soa != null || ns == null) {
			/* Negative response */
                cred = getCred(DnsSection.AUTHORITY, isAuth);
                SOARecord soarec = null;
                if (soa != null) {
                    soarec = (SOARecord) soa.first();
                }
                addNegative(curname, cachetype, soarec, cred);
                if (response == null) {
                    int responseType;
                    if (rcode == DnsResponseCode.NXDOMAIN) {
                        responseType = SetResponse.NXDOMAIN;
                    }
                    else {
                        responseType = SetResponse.NXRRSET;
                    }
                    response = SetResponse.ofType(responseType);
                }
			/* DNSSEC records are not cached. */
            }
            else {
			/* Referral response */
                cred = getCred(DnsSection.AUTHORITY, isAuth);
                addRRset(ns, cred);
                markAdditional(ns, additionalNames);
                if (response == null) {
                    response = new SetResponse(SetResponse.DELEGATION, ns);
                }
            }
        }
        else if (rcode == DnsResponseCode.NOERROR && ns != null) {
		/* Cache the NS set from a positive response. */
            cred = getCred(DnsSection.AUTHORITY, isAuth);
            addRRset(ns, cred);
            markAdditional(ns, additionalNames);
        }

        addl = in.getSectionRRsets(DnsSection.ADDITIONAL);
        for (int i = 0; i < addl.length; i++) {
            int type = addl[i].getType();
            if (type != DnsRecordType.A && type != DnsRecordType.AAAA && type != DnsRecordType.A6) {
                continue;
            }
            Name name = addl[i].getName();
            if (!additionalNames.contains(name)) {
                continue;
            }
            cred = getCred(DnsSection.ADDITIONAL, isAuth);
            addRRset(addl[i], cred);
        }
        if (verbose) {
            System.out.println("addMessage: " + response);
        }
        return (response);
    }

    /**
     * Flushes an RRset from the cache
     *
     * @param name The name of the records to be flushed
     * @param type The type of the records to be flushed
     *
     * @see RRset
     */
    public
    void flushSet(Name name, int type) {
        removeElement(name, type);
    }

    /**
     * Flushes all RRsets with a given name from the cache
     *
     * @param name The name of the records to be flushed
     *
     * @see RRset
     */
    public
    void flushName(Name name) {
        removeName(name);
    }

    private synchronized
    void removeName(Name name) {
        data.remove(name);
    }

    /**
     * Gets the maximum length of time that a negative response will be stored
     * in this Cache.  A negative value indicates no limit.
     */
    public
    int getMaxNCache() {
        return maxncache;
    }

    /**
     * Sets the maximum length of time that a negative response will be stored
     * in this Cache.  A negative value disables this feature (that is, sets
     * no limit).
     */
    public
    void setMaxNCache(int seconds) {
        maxncache = seconds;
    }

    /**
     * Gets the maximum length of time that records will be stored
     * in this Cache.  A negative value indicates no limit.
     */
    public
    int getMaxCache() {
        return maxcache;
    }

    /**
     * Sets the maximum length of time that records will be stored in this
     * Cache.  A negative value disables this feature (that is, sets no limit).
     */
    public
    void setMaxCache(int seconds) {
        maxcache = seconds;
    }

    /**
     * Gets the current number of entries in the Cache, where an entry consists
     * of all records with a specific Name.
     */
    public
    int getSize() {
        return data.size();
    }

    /**
     * Gets the maximum number of entries in the Cache, where an entry consists
     * of all records with a specific Name.  A negative value is treated as an
     * infinite limit.
     */
    public
    int getMaxEntries() {
        return data.getMaxSize();
    }

    /**
     * Sets the maximum number of entries in the Cache, where an entry consists
     * of all records with a specific Name.  A negative value is treated as an
     * infinite limit.
     * <p>
     * Note that setting this to a value lower than the current number
     * of entries will not cause the Cache to shrink immediately.
     * <p>
     * The default maximum number of entries is 50000.
     *
     * @param entries The maximum number of entries in the Cache.
     */
    public
    void setMaxEntries(int entries) {
        data.setMaxSize(entries);
    }

    /**
     * Returns the DNS class of this cache.
     */
    public
    int getDClass() {
        return dclass;
    }

    /**
     * Returns the contents of the Cache as a string.
     */
    public
    String toString() {
        StringBuilder sb = new StringBuilder();
        synchronized (this) {
            Iterator it = data.values()
                              .iterator();

            while (it.hasNext()) {
                Element[] elements = allElements(it.next());
                for (int i = 0; i < elements.length; i++) {
                    sb.append(elements[i]);
                    sb.append("\n");
                }
            }
        }
        return sb.toString();
    }

}
