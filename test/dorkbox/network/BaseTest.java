/* Copyright (c) 2008, Nathan Sweet
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following
 * conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided with the distribution.
 * - Neither the name of Esoteric Software nor the names of its contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
 * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package dorkbox.network;


import static org.junit.Assert.fail;

import java.util.ArrayList;

import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.ConsoleAppender;
import dorkbox.network.util.Shutdownable;
import dorkbox.util.entropy.Entropy;
import dorkbox.util.entropy.SimpleEntropy;
import dorkbox.util.exceptions.InitializationException;
import io.netty.util.ResourceLeakDetector;

public abstract
class BaseTest {

    public static final String host = "127.0.0.1";
    public static final int tcpPort = 54558;
    public static final int udpPort = 54779;

    static {
        // we want our entropy generation to be simple (ie, no user interaction to generate)
        try {
            Entropy.init(SimpleEntropy.class);
        } catch (InitializationException e) {
            e.printStackTrace();
        }
    }

    volatile boolean fail_check;
    private final ArrayList<Shutdownable> endPointConnections = new ArrayList<Shutdownable>();

    public
    BaseTest() {
        ResourceLeakDetector.setLevel(ResourceLeakDetector.Level.PARANOID);

        System.out.println("---- " + getClass().getSimpleName());

        // assume SLF4J is bound to logback in the current environment
        Logger rootLogger = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        LoggerContext context = rootLogger.getLoggerContext();

        JoranConfigurator jc = new JoranConfigurator();
        jc.setContext(context);
        context.reset(); // override default configuration

//        rootLogger.setLevel(Level.OFF);

        // rootLogger.setLevel(Level.INFO);
        rootLogger.setLevel(Level.DEBUG);
       // rootLogger.setLevel(Level.TRACE);
//        rootLogger.setLevel(Level.ALL);


        // we only want error messages
        Logger nettyLogger = (Logger) LoggerFactory.getLogger("io.netty");
        nettyLogger.setLevel(Level.ERROR);

        // we only want error messages
        Logger kryoLogger = (Logger) LoggerFactory.getLogger("com.esotericsoftware");
        kryoLogger.setLevel(Level.ERROR);

        // we only want error messages
        Logger barchartLogger = (Logger) LoggerFactory.getLogger("com.barchart");
        barchartLogger.setLevel(Level.ERROR);

        PatternLayoutEncoder encoder = new PatternLayoutEncoder();
        encoder.setContext(context);
        encoder.setPattern("%date{HH:mm:ss.SSS}  %-5level [%logger{35}] %msg%n");
        encoder.start();

        ConsoleAppender<ILoggingEvent> consoleAppender = new ch.qos.logback.core.ConsoleAppender<ILoggingEvent>();

        consoleAppender.setContext(context);
        consoleAppender.setEncoder(encoder);
        consoleAppender.start();

        rootLogger.addAppender(consoleAppender);
    }

    public
    void addEndPoint(final Shutdownable endPointConnection) {
        this.endPointConnections.add(endPointConnection);
    }

    /**
     * Immediately stop the endpoints
     */
    public
    void stopEndPoints() {
        stopEndPoints(0);
    }

    public
    void stopEndPoints(final int stopAfterMillis) {
        ThreadGroup threadGroup = Thread.currentThread()
                                        .getThreadGroup();
        final String name = threadGroup.getName();

        if (name.contains(Shutdownable.THREADGROUP_NAME)) {
            // We have to ALWAYS run this in a new thread, BECAUSE if stopEndPoints() is called from a client/server thread, it will
            // DEADLOCK
            final Thread thread = new Thread(threadGroup.getParent(), new Runnable() {
                @Override
                public
                void run() {
                    try {
                        // not the best, but this works for our purposes. This is a TAD hacky, because we ALSO have to make sure that we
                        // ARE NOT in the same thread group as netty!
                        Thread.sleep(stopAfterMillis);

                        stopEndPoints(stopAfterMillis);
                    } catch (InterruptedException ignored) {
                    }
                }
            }, "UnitTest shutdown");

            thread.setDaemon(true);
            thread.start();
        } else {
            synchronized (this.endPointConnections) {
                for (Shutdownable endPointConnection : this.endPointConnections) {
                    endPointConnection.stop();
                    endPointConnection.waitForShutdown();
                }

                this.endPointConnections.clear();
                this.endPointConnections.notifyAll();
            }
        }
    }

    /**
     * Wait for network client/server threads to shutdown on their own, BUT WILL ERROR (+ shutdown) if they take longer than 2 minutes.
     */
    public
    void waitForThreads() {
        waitForThreads(0);
    }

    /**
     * Wait for network client/server threads to shutdown for the specified time.
     *
     * @param stopAfterSeconds how many seconds to wait
     */
    public
    void waitForThreads(int stopAfterSeconds) {
        final int stopAfterMillis = stopAfterSeconds * 1000; // this must be in milliseconds

        this.fail_check = false;

        synchronized (this.endPointConnections) {
            Thread thread = null;
            if (!this.endPointConnections.isEmpty()) {
                // make sure to run this thread in the MAIN thread group..
                ThreadGroup threadGroup = Thread.currentThread()
                                                .getThreadGroup();
                if (threadGroup.getName()
                               .contains(Shutdownable.THREADGROUP_NAME)) {
                    threadGroup = threadGroup.getParent();
                }

                thread = new Thread(threadGroup, new Runnable() {
                    @Override
                    public
                    void run() {
                        // not the best, but this works for our purposes. This is a TAD hacky, because we ALSO have to make sure that we
                        // ARE NOT in the same thread group as netty!
                        try {
                            if (stopAfterMillis > 0L) {
                                // if we specify a time, then we stop, otherwise we wait the timeout.
                                Thread.sleep(stopAfterMillis);
                            }
                            else {
                                Thread.sleep(120 * 1000L); // wait minimum of 2 minutes before we automatically fail the unit test.
                            }

                            System.err.println("Test did not complete in a timely manner...");
                            BaseTest.this.fail_check = true;
                            stopEndPoints();
                        } catch (InterruptedException ignored) {
                        }
                    }
                }, "UnitTest timeout fail condition");
                thread.setDaemon(true);
                thread.start();
            }

            while (!this.endPointConnections.isEmpty()) {
                try {
                    this.endPointConnections.wait(stopAfterMillis);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            if (thread != null) {
                thread.interrupt();
            }

            if (this.fail_check) {
                fail("Test did not complete in a timely manner.");
            }
        }

        // Give sockets a chance to close before starting the next test.
        try {
            Thread.sleep(1000);
        } catch (InterruptedException ignored) {
        }
    }
}
