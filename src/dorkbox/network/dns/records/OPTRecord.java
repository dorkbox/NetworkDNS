// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package dorkbox.network.dns.records;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import dorkbox.network.dns.Compression;
import dorkbox.network.dns.DnsInput;
import dorkbox.network.dns.DnsOutput;
import dorkbox.network.dns.Name;
import dorkbox.network.dns.constants.DnsRecordType;
import dorkbox.network.dns.constants.DnsResponseCode;
import dorkbox.network.dns.constants.ExtendedFlags;
import dorkbox.network.dns.utils.Tokenizer;

/**
 * Options - describes Extended DNS (EDNS) properties of a DnsMessage.
 * No specific options are defined other than those specified in the
 * header.  An OPT should be generated by Resolver.
 * <p>
 * EDNS is a method to extend the DNS protocol while providing backwards
 * compatibility and not significantly changing the protocol.  This
 * implementation of EDNS is mostly complete at level 0.
 *
 * @author Brian Wellington
 * @see DnsMessage
 */

public
class OPTRecord extends DnsRecord {

    private static final long serialVersionUID = -6254521894809367938L;

    private List options;

    OPTRecord() {}

    @Override
    DnsRecord getObject() {
        return new OPTRecord();
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
        if (in.remaining() > 0) {
            options = new ArrayList();
        }
        while (in.remaining() > 0) {
            EDNSOption option = EDNSOption.fromWire(in);
            options.add(option);
        }
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        if (options == null) {
            return;
        }
        Iterator it = options.iterator();
        while (it.hasNext()) {
            EDNSOption option = (EDNSOption) it.next();
            option.toWire(out);
        }
    }

    /**
     * Converts rdata to a String
     */
    @Override
    void rrToString(StringBuilder sb) {
        if (options != null) {
            sb.append(options);
            sb.append(" ");
        }

        sb.append(" ; payload ");
        sb.append(getPayloadSize());
        sb.append(", xrcode ");
        sb.append(getExtendedRcode());
        sb.append(", version ");
        sb.append(getVersion());
        sb.append(", flags ");
        sb.append(getFlags());
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        throw st.exception("no text format defined for OPT");
    }

    /**
     * Determines if two OPTRecords are identical.  This compares the name, type,
     * class, and rdata (with names canonicalized).  Additionally, because TTLs
     * are relevant for OPT records, the TTLs are compared.
     *
     * @param arg The record to compare to
     *
     * @return true if the records are equal, false otherwise.
     */
    @Override
    public
    boolean equals(final Object arg) {
        return super.equals(arg) && ttl == ((OPTRecord) arg).ttl;
    }

    /**
     * Returns the maximum allowed payload size.
     */
    public
    int getPayloadSize() {
        return dclass;
    }

    /**
     * Returns the extended DnsResponseCode
     *
     * @see DnsResponseCode
     */
    public
    int getExtendedRcode() {
        return (int) (ttl >>> 24);
    }

    /**
     * Returns the highest supported EDNS version
     */
    public
    int getVersion() {
        return (int) ((ttl >>> 16) & 0xFF);
    }

    /**
     * Returns the EDNS flags
     */
    public
    int getFlags() {
        return (int) (ttl & 0xFFFF);
    }

    /**
     * Creates an OPT Record with no data.  This is normally called by
     * SimpleResolver, but can also be called by a server.
     *
     * @param payloadSize The size of a packet that can be reassembled on the
     *         sending host.
     * @param xrcode The value of the extended rcode field.  This is the upper
     *         16 bits of the full rcode.
     * @param flags Additional message flags.
     * @param version The EDNS version that this DNS implementation supports.
     *         This should be 0 for dnsjava.
     *
     * @see ExtendedFlags
     */
    public
    OPTRecord(int payloadSize, int xrcode, int version, int flags) {
        this(payloadSize, xrcode, version, flags, null);
    }

    /**
     * Creates an OPT Record.  This is normally called by SimpleResolver, but can
     * also be called by a server.
     *
     * @param payloadSize The size of a packet that can be reassembled on the
     *         sending host.
     * @param xrcode The value of the extended rcode field.  This is the upper
     *         16 bits of the full rcode.
     * @param flags Additional message flags.
     * @param version The EDNS version that this DNS implementation supports.
     *         This should be 0 for dnsjava.
     * @param options The list of options that comprise the data field.  There
     *         are currently no defined options.
     *
     * @see ExtendedFlags
     */
    public
    OPTRecord(int payloadSize, int xrcode, int version, int flags, List options) {
        super(Name.root, DnsRecordType.OPT, payloadSize, 0);
        checkU16("payloadSize", payloadSize);
        checkU8("xrcode", xrcode);
        checkU8("version", version);
        checkU16("flags", flags);
        ttl = ((long) xrcode << 24) + ((long) version << 16) + flags;
        if (options != null) {
            this.options = new ArrayList(options);
        }
    }

    /**
     * Creates an OPT Record with no data.  This is normally called by
     * SimpleResolver, but can also be called by a server.
     */
    public
    OPTRecord(int payloadSize, int xrcode, int version) {
        this(payloadSize, xrcode, version, 0, null);
    }

    /**
     * Gets all options in the OPTRecord.  This returns a list of EDNSOptions.
     */
    public
    List getOptions() {
        if (options == null) {
            return Collections.EMPTY_LIST;
        }
        return Collections.unmodifiableList(options);
    }

    /**
     * Gets all options in the OPTRecord with a specific code.  This returns a list
     * of EDNSOptions.
     */
    public
    List getOptions(int code) {
        if (options == null) {
            return Collections.EMPTY_LIST;
        }
        List list = Collections.EMPTY_LIST;
        for (Iterator it = options.iterator(); it.hasNext(); ) {
            EDNSOption opt = (EDNSOption) it.next();
            if (opt.getCode() == code) {
                if (list == Collections.EMPTY_LIST) {
                    list = new ArrayList();
                }
                list.add(opt);
            }
        }
        return list;
    }

}
