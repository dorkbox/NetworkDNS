/*
 * Copyright 2021 dorkbox, llc
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
package dorkbox.dns.util;

// import static dorkbox.network.pipeline.ConnectionType.EPOLL;
// import static dorkbox.network.pipeline.ConnectionType.KQUEUE;
// import static dorkbox.network.pipeline.ConnectionType.NIO;
// import static dorkbox.network.pipeline.ConnectionType.OIO;

import java.security.AccessControlException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;

import dorkbox.dns.DnsClient;
import dorkbox.os.OS;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.EventLoopGroup;
import io.netty.util.concurrent.EventExecutor;
import io.netty.util.concurrent.Future;

// import dorkbox.network.pipeline.ConnectionType;

/**
 * This is the highest level endpoint, for lifecycle support/management.
 */
public
class Shutdownable {
    static {
        //noinspection Duplicates
        try {
            // doesn't work when running from inside eclipse.
            // Needed for NIO selectors on Android 2.2, and to force IPv4.
            System.setProperty("java.net.preferIPv4Stack", Boolean.TRUE.toString());
            System.setProperty("java.net.preferIPv6Addresses", Boolean.FALSE.toString());

        } catch (AccessControlException ignored) {
        }
    }


    protected static final String shutdownHookName = "::SHUTDOWN_HOOK::";
    protected static final String stopTreadName = "::STOP_THREAD::";

    public static final String THREADGROUP_NAME = "(Netty)";

    /**
     * This is used to enable the usage of native libraries for an OS that supports them.
     */
    public static volatile boolean enableNativeLibrary = OS.getBoolean(DnsClient.class.getCanonicalName() + ".enableNativeLibrary", true);

    /**
     * The HIGH and LOW watermark points for connections
     */
    public static volatile int WRITE_BUFF_HIGH = OS.getInt(Shutdownable.class.getCanonicalName() + ".WRITE_BUFF_HIGH", 32 * 1024);

    public static volatile int WRITE_BUFF_LOW = OS.getInt(Shutdownable.class.getCanonicalName() + ".WRITE_BUFF_LOW", 8 * 1024);

    /**
     * The amount of time in milli-seconds to wait for this endpoint to close all {@link Channel}s and shutdown gracefully.
     */
    public static volatile long maxShutdownWaitTimeInMilliSeconds = OS.getLong(Shutdownable.class.getCanonicalName() + ".maxShutdownWaitTimeInMilliSeconds", 2000L); // in milliseconds

    // /**
    //  * Checks to see if we are running in the netty thread. This is (usually) to prevent potential deadlocks in code that CANNOT be run from
    //  * inside a netty worker.
    //  */
    // public static
    // boolean isNettyThread() {
    //     return Thread.currentThread()
    //                  .getThreadGroup()
    //                  .getName()
    //                  .contains(THREADGROUP_NAME);
    // }

    // /**
    //  * Runs a runnable inside a NEW thread that is NOT in the same thread group as Netty
    //  */
    // public static
    // void runNewThread(final String threadName, final Runnable runnable) {
    //     Thread thread = new Thread(Thread.currentThread()
    //                                      .getThreadGroup()
    //                                      .getParent(),
    //                                runnable);
    //     thread.setDaemon(true);
    //     thread.setName(threadName);
    //     thread.start();
    // }

    protected final Logger logger;

    protected final ThreadGroup threadGroup;

    protected final Class<? extends Shutdownable> type;

    protected final Object shutdownInProgress = new Object();
    private volatile boolean isShutdown = false;

    // the eventLoop groups are used to track and manage the event loops for startup/shutdown
    private final List<EventLoopGroup> eventLoopGroups = new ArrayList<EventLoopGroup>(8);
    private final List<ChannelFuture> shutdownChannelList = new ArrayList<ChannelFuture>();

    // make sure that the endpoint is closed on JVM shutdown (if it's still open at that point in time)
    private Thread shutdownHook;

    private final CountDownLatch blockUntilDone = new CountDownLatch(1);

    private AtomicBoolean stopCalled = new AtomicBoolean(false);

    public
    Shutdownable(final Class<? extends Shutdownable> type) {
        this.type = type;

        // setup the thread group to easily ID what the following threads belong to (and their spawned threads...)
        SecurityManager s = System.getSecurityManager();
        threadGroup = new ThreadGroup(s != null
                                      ? s.getThreadGroup()
                                      : Thread.currentThread()
                                              .getThreadGroup(), type.getSimpleName() + " " + THREADGROUP_NAME);
        threadGroup.setDaemon(true);

        logger = org.slf4j.LoggerFactory.getLogger(type.getSimpleName());


        shutdownHook = new Thread() {
            @Override
            public
            void run() {
                if (Shutdownable.this.shouldShutdownHookRun()) {
                    Shutdownable.this.stop();
                }
            }
        };
        shutdownHook.setName(shutdownHookName);
        try {
            Runtime.getRuntime()
                   .addShutdownHook(shutdownHook);
        } catch (Throwable ignored) {
            // if we are in the middle of shutdown, we cannot do this.
        }
    }

    /**
     * Add a channel future to be tracked and managed for shutdown.
     */
    protected final
    void manageForShutdown(ChannelFuture future) {
        synchronized (shutdownChannelList) {
            shutdownChannelList.add(future);
        }
    }

    /**
     * Add an eventloop group to be tracked & managed for shutdown
     */
    protected final
    void manageForShutdown(EventLoopGroup loopGroup) {
        synchronized (eventLoopGroups) {
            eventLoopGroups.add(loopGroup);
        }
    }

    /**
     * Remove an eventloop group to be tracked & managed for shutdown
     */
    protected final
    void removeFromShutdown(EventLoopGroup loopGroup) {
        synchronized (eventLoopGroups) {
            eventLoopGroups.remove(loopGroup);
        }
    }

    // server only does this on stop. Client does this on closeConnections
    void shutdownAllChannels() {
        synchronized (shutdownChannelList) {
            // now we stop all of our channels. For the server, this will close the server manager for UDP sessions
            for (ChannelFuture f : shutdownChannelList) {
                Channel channel = f.channel();
                if (channel.isOpen()) {
                    // from the git example on how to shutdown a channel
                    channel.close().syncUninterruptibly();
                    Thread.yield();
                }
            }

            // we have to clear the shutdown list. (
            shutdownChannelList.clear();
        }
    }

    // shutdown all event loops associated
    void shutdownEventLoops() {
        // we want to WAIT until after the event executors have completed shutting down.
        List<Future<?>> shutdownThreadList = new LinkedList<Future<?>>();

        List<EventLoopGroup> loopGroups;
        synchronized (eventLoopGroups) {
            loopGroups = new ArrayList<EventLoopGroup>(eventLoopGroups.size());
            loopGroups.addAll(eventLoopGroups);
        }

        for (EventLoopGroup loopGroup : loopGroups) {
            Future<?> future = loopGroup.shutdownGracefully(maxShutdownWaitTimeInMilliSeconds / 10, maxShutdownWaitTimeInMilliSeconds, TimeUnit.MILLISECONDS);
            shutdownThreadList.add(future);
            Thread.yield();
        }

        // now wait for them to finish!
        // It can take a few seconds to shut down the executor. This will affect unit testing, where connections are quickly created/stopped
        for (Future<?> f : shutdownThreadList) {
            try {
                f.await(maxShutdownWaitTimeInMilliSeconds);
            } catch (InterruptedException ignored) {
            }
            Thread.yield();
        }
    }

    protected final
    String stopWithErrorMessage(Logger logger, String errorMessage, Throwable throwable) {
        if (logger.isDebugEnabled() && throwable != null) {
            // extra info if debug is enabled
            logger.error(errorMessage, throwable.getCause());
        }
        else {
            logger.error(errorMessage);
        }

        stop();
        return errorMessage;
    }

    /**
     * Starts the shutdown process during JVM shutdown, if necessary.
     * </p>
     * By default, we always can shutdown via the JVM shutdown hook.
     */
    protected
    boolean shouldShutdownHookRun() {
        return true;
    }

    /**
     * Check to see if the current thread is running from it's OWN thread, or from Netty... This is used to prevent deadlocks.
     *
     * @return true if the specified thread is as Netty thread, false if it's own thread.
     */
    protected
    boolean isInEventLoop(Thread thread) {
        for (EventLoopGroup loopGroup : eventLoopGroups) {
            for (EventExecutor next : loopGroup) {
                if (next.inEventLoop(thread)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Safely closes all associated resources/threads/connections.
     * <p/>
     * If we want to WAIT for this endpoint to shutdown, we must explicitly call waitForShutdown()
     * <p/>
     * Override stopExtraActions() if you want to provide extra behavior while stopping the endpoint
     */
    public final
    void stop() {
        // only permit us to "stop" once!
        if (!stopCalled.compareAndSet(false, true)) {
            return;
        }

        // check to make sure we are in our OWN thread, otherwise, this thread will never exit -- because it will wait indefinitely
        // for itself to finish (since it blocks itself).
        // This occurs when calling stop from within a listener callback.
        Thread currentThread = Thread.currentThread();
        String threadName = currentThread.getName();
        boolean isShutdownThread = !threadName.equals(shutdownHookName) && !threadName.equals(stopTreadName);

        // used to check the event groups to see if we are running from one of them. NOW we force to
        // ALWAYS shutdown inside a NEW thread
        if (!isShutdownThread || !isInEventLoop(currentThread)) {
            stopInThread();
        }
        else {
            Thread thread = new Thread(new Runnable() {
                @Override
                public
                void run() {
                    Shutdownable.this.stopInThread();
                }
            });
            thread.setDaemon(false);
            thread.setName(stopTreadName);
            thread.start();
        }
    }

    /**
     * Extra EXTERNAL actions to perform when stopping this endpoint.
     */
    protected
    void stopExtraActions() {
    }

    /**
     * Actions that happen by the endpoint before the channels are shutdown
     */
    protected
    void shutdownChannelsPre() {
    }


    /**
     * Actions that happen by the endpoint before any extra actions are run.
     */
    protected
    void stopExtraActionsInternal() {
    }

    // This actually does the "stopping", since there is some logic to making sure we don't deadlock, this is important
    private
    void stopInThread() {
        // make sure we are not trying to stop during a startup procedure.
        // This will wait until we have finished starting up/shutting down.
        synchronized (shutdownInProgress) {
            shutdownChannelsPre();
            shutdownAllChannels();
            shutdownEventLoops();

            logger.info("Stopping endpoint.");

            // there is no need to call "stop" again if we close the connection.
            // however, if this is called WHILE from the shutdown hook, blammo! problems!

            // Also, you can call client/server.stop from another thread, which is run when the JVM is shutting down
            // (as there is nothing left to do), and also have problems.
            if (!Thread.currentThread()
                       .getName()
                       .equals(shutdownHookName)) {
                try {
                    Runtime.getRuntime()
                           .removeShutdownHook(shutdownHook);
                } catch (Exception e) {
                    // ignore
                }
            }

            stopExtraActionsInternal();

            // when the eventloop closes, the associated selectors are ALSO closed!
            stopExtraActions();

            isShutdown = true;
        }

        // tell the blocked "bind" method that it may continue (and exit)
        blockUntilDone.countDown();
    }

    /**
     * Blocks the current thread until the endpoint has been stopped. If the endpoint is already stopped, this do nothing.
     */
    public final
    void waitForShutdown() {
        // we now BLOCK until the stop method is called.
        try {
            blockUntilDone.await();
        } catch (InterruptedException e) {
            logger.error("Thread interrupted while waiting for stop!");
        }
    }

    /**
     * @return true if we have already shutdown, false otherwise
     */
    public final
    boolean isShutdown() {
        synchronized (shutdownInProgress) {
            return isShutdown;
        }
    }

    @Override
    public
    String toString() {
        return "EndPoint [" + getName() + "]";
    }

    public
    String getName() {
        return type.getSimpleName();
    }
}
