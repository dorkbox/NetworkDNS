module dorkbox.dns {
    exports dorkbox.dns;
    exports dorkbox.dns.dns.constants;
    exports dorkbox.dns.dns.exceptions;
    exports dorkbox.dns.dns.records;

    requires dorkbox.netutil;
    requires dorkbox.utilities;
    requires dorkbox.collections;
    requires dorkbox.updates;
    requires dorkbox.os;

    requires io.netty.codec;
    requires org.slf4j;

    requires io.netty.transport;
    requires io.netty.transport.classes.epoll;
    requires io.netty.transport.classes.kqueue;
    requires io.netty.common;
    requires io.netty.buffer;
    requires io.netty.resolver;
}
