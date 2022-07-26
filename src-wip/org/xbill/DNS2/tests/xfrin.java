// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package org.xbill.DNS2.tests;

import java.util.Iterator;
import java.util.List;

import org.xbill.DNS2.clients.Lookup;
import org.xbill.DNS2.clients.ZoneTransferIn;
import org.xbill.DNS2.resolver.SimpleResolver;

import dorkbox.network.dns.Name;
import dorkbox.network.dns.constants.DnsRecordType;
import dorkbox.network.dns.records.DnsRecord;
import dorkbox.network.dns.records.TSIG;

public
class xfrin {

    public static
    void main(String[] args) throws Exception {
        ZoneTransferIn xfrin;
        TSIG key = null;
        int ixfr_serial = -1;
        String server = null;
        int port = SimpleResolver.DEFAULT_PORT;
        boolean fallback = false;
        Name zname;

        int arg = 0;
        while (arg < args.length) {
            if (args[arg].equals("-i")) {
                ixfr_serial = Integer.parseInt(args[++arg]);
                if (ixfr_serial < 0) {
                    usage("invalid serial number");
                }
            }
            else if (args[arg].equals("-k")) {
                String s = args[++arg];
                int index = s.indexOf('/');
                if (index < 0) {
                    usage("invalid key");
                }
                key = new TSIG(s.substring(0, index), s.substring(index + 1));
            }
            else if (args[arg].equals("-s")) {
                server = args[++arg];
            }
            else if (args[arg].equals("-p")) {
                port = Integer.parseInt(args[++arg]);
                if (port < 0 || port > 0xFFFF) {
                    usage("invalid port");
                }
            }
            else if (args[arg].equals("-f")) {
                fallback = true;
            }
            else if (args[arg].startsWith("-")) {
                usage("invalid option");
            }
            else {
                break;
            }
            arg++;
        }
        if (arg >= args.length) {
            usage("no zone name specified");
        }
        zname = Name.Companion.fromString(args[arg]);

        if (server == null) {
            Lookup l = new Lookup(zname, DnsRecordType.NS);
            DnsRecord[] ns = l.run();
            if (ns == null) {
                System.out.println("failed to look up NS record: " + l.getErrorString());
                System.exit(1);
            }
            StringBuilder stringBuilder = new StringBuilder();
            ns[0].rdataToString(stringBuilder);

            server = stringBuilder.toString();
            System.out.println("sending to server '" + server + "'");
        }

        if (ixfr_serial >= 0) {
            xfrin = ZoneTransferIn.newIXFR(zname, ixfr_serial, fallback, server, port, key);
        }
        else {
            xfrin = ZoneTransferIn.newAXFR(zname, server, port, key);
        }

        List response = xfrin.run();
        if (xfrin.isAXFR()) {
            if (ixfr_serial >= 0) {
                System.out.println("AXFR-like IXFR response");
            }
            else {
                System.out.println("AXFR response");
            }
            Iterator it = response.iterator();
            while (it.hasNext()) {
                System.out.println(it.next());
            }
        }
        else if (xfrin.isIXFR()) {
            System.out.println("IXFR response");
            Iterator it = response.iterator();
            while (it.hasNext()) {
                ZoneTransferIn.Delta delta;
                delta = (ZoneTransferIn.Delta) it.next();
                System.out.println("delta from " + delta.start + " to " + delta.end);
                System.out.println("deletes");
                Iterator it2 = delta.deletes.iterator();
                while (it2.hasNext()) {
                    System.out.println(it2.next());
                }
                System.out.println("adds");
                it2 = delta.adds.iterator();
                while (it2.hasNext()) {
                    System.out.println(it2.next());
                }
            }
        }
        else if (xfrin.isCurrent()) {
            System.out.println("up to date");
        }
    }

    private static
    void usage(String s) {
        System.out.println("Error: " + s);
        System.out.println("usage: xfrin [-i serial] [-k keyname/secret] " + "[-s server] [-p port] [-f] zone");
        System.exit(1);
    }

}
