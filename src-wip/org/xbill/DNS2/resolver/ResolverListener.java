// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS2.resolver;

import java.util.EventListener;

import dorkbox.network.dns.records.DnsMessage;

/**
 * An interface to the asynchronous resolver.
 *
 * @author Brian Wellington
 * @see Resolver
 */

public
interface ResolverListener extends EventListener {

    /**
     * The callback used by an asynchronous resolver
     *
     * @param id The identifier returned by Resolver.sendAsync()
     * @param m The response message as returned by the Resolver
     */
    void receiveMessage(Object id, DnsMessage m);

    /**
     * The callback used by an asynchronous resolver when an exception is thrown
     *
     * @param id The identifier returned by Resolver.sendAsync()
     * @param e The thrown exception
     */
    void handleException(Object id, Exception e);

}
