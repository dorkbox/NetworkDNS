// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS2.resolver;

import dorkbox.network.dns.records.DnsMessage;

/**
 * A special-purpose thread used by Resolvers (both SimpleResolver and
 * ExtendedResolver) to perform asynchronous queries.
 *
 * @author Brian Wellington
 */

class ResolveThread extends Thread {

    private DnsMessage query;
    private Object id;
    private ResolverListener listener;
    private Resolver res;

    /**
     * Creates a new ResolveThread
     */
    public
    ResolveThread(Resolver res, DnsMessage query, Object id, ResolverListener listener) {
        this.res = res;
        this.query = query;
        this.id = id;
        this.listener = listener;
    }


    /**
     * Performs the query, and executes the callback.
     */
    @Override
    public
    void run() {
        try {
            DnsMessage response = res.send(query);
            listener.receiveMessage(id, response);
        } catch (Exception e) {
            listener.handleException(id, e);
        }
    }

}
