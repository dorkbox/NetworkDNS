module dorkbox.dns {
    exports dorkbox.dns;
    exports dorkbox.dns.dns.constants;
    exports dorkbox.dns.dns.exceptions;
    exports dorkbox.dns.dns.records;

    requires dorkbox.netutil;
    requires dorkbox.utilities;
    requires dorkbox.updates;

    requires io.netty.all;
    requires org.slf4j;
}
