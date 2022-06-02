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
package dorkbox.dns.util

import dorkbox.dns.DnsClient
import dorkbox.os.OS.getBoolean
import dorkbox.os.OS.getInt
import dorkbox.os.OS.getLong
import io.netty.channel.ChannelFuture
import io.netty.channel.EventLoopGroup
import io.netty.util.concurrent.Future
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.security.AccessControlException
import java.util.*
import java.util.concurrent.*
import java.util.concurrent.atomic.*

// import static dorkbox.network.pipeline.ConnectionType.EPOLL;
// import static dorkbox.network.pipeline.ConnectionType.KQUEUE;
// import static dorkbox.network.pipeline.ConnectionType.NIO;
// import static dorkbox.network.pipeline.ConnectionType.OIO;
// import dorkbox.network.pipeline.ConnectionType;
/**
 * This is the highest level endpoint, for lifecycle support/management.
 */
open class Shutdownable(protected val type: Class<out Shutdownable?>) {
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

    companion object {
        init {
            try {
                // doesn't work when running from inside eclipse.
                // Needed for NIO selectors on Android 2.2, and to force IPv4.
                System.setProperty("java.net.preferIPv4Stack", java.lang.Boolean.TRUE.toString())
                System.setProperty("java.net.preferIPv6Addresses", java.lang.Boolean.FALSE.toString())
            } catch (ignored: AccessControlException) {
            }
        }

        protected const val shutdownHookName = "::SHUTDOWN_HOOK::"
        protected const val stopTreadName = "::STOP_THREAD::"
        const val THREADGROUP_NAME = "(Netty)"

        /**
         * This is used to enable the usage of native libraries for an OS that supports them.
         */
        @Volatile
        var enableNativeLibrary = getBoolean(DnsClient::class.java.canonicalName + ".enableNativeLibrary", true)

        /**
         * The HIGH and LOW watermark points for connections
         */
        @Volatile
        var WRITE_BUFF_HIGH = getInt(Shutdownable::class.java.canonicalName + ".WRITE_BUFF_HIGH", 32 * 1024)

        @Volatile
        var WRITE_BUFF_LOW = getInt(Shutdownable::class.java.canonicalName + ".WRITE_BUFF_LOW", 8 * 1024)

        /**
         * The amount of time in milli-seconds to wait for this endpoint to close all [Channel]s and shutdown gracefully.
         */
        @Volatile
        var maxShutdownWaitTimeInMilliSeconds =
            getLong(Shutdownable::class.java.canonicalName + ".maxShutdownWaitTimeInMilliSeconds", 2000L) // in milliseconds
    }

    protected val logger: Logger
    protected val threadGroup: ThreadGroup
    protected val shutdownInProgress = Any()

    @Volatile
    private var isShutdown = false

    // the eventLoop groups are used to track and manage the event loops for startup/shutdown
    private val eventLoopGroups: MutableList<EventLoopGroup> = ArrayList(8)
    private val shutdownChannelList: MutableList<ChannelFuture> = ArrayList()

    // make sure that the endpoint is closed on JVM shutdown (if it's still open at that point in time)
    private val shutdownHook: Thread
    private val blockUntilDone = CountDownLatch(1)
    private val stopCalled = AtomicBoolean(false)


    init {
        // setup the thread group to easily ID what the following threads belong to (and their spawned threads...)
        val s = System.getSecurityManager()
        threadGroup = ThreadGroup(
            if (s != null) s.threadGroup else Thread.currentThread().threadGroup, type.simpleName + " " + THREADGROUP_NAME
        )
        threadGroup.isDaemon = true
        logger = LoggerFactory.getLogger(type.simpleName)
        shutdownHook = object : Thread() {
            override fun run() {
                if (shouldShutdownHookRun()) {
                    this@Shutdownable.stop()
                }
            }
        }
        shutdownHook.setName(shutdownHookName)
        try {
            Runtime.getRuntime().addShutdownHook(shutdownHook)
        } catch (ignored: Throwable) {
            // if we are in the middle of shutdown, we cannot do this.
        }
    }

    /**
     * Add a channel future to be tracked and managed for shutdown.
     */
    protected fun manageForShutdown(future: ChannelFuture) {
        synchronized(shutdownChannelList) { shutdownChannelList.add(future) }
    }

    /**
     * Add an eventloop group to be tracked & managed for shutdown
     */
    protected fun manageForShutdown(loopGroup: EventLoopGroup) {
        synchronized(eventLoopGroups) { eventLoopGroups.add(loopGroup) }
    }

    /**
     * Remove an eventloop group to be tracked & managed for shutdown
     */
    protected fun removeFromShutdown(loopGroup: EventLoopGroup) {
        synchronized(eventLoopGroups) { eventLoopGroups.remove(loopGroup) }
    }

    // server only does this on stop. Client does this on closeConnections
    fun shutdownAllChannels() {
        synchronized(shutdownChannelList) {

            // now we stop all of our channels. For the server, this will close the server manager for UDP sessions
            for (f in shutdownChannelList) {
                val channel = f.channel()
                if (channel.isOpen) {
                    // from the git example on how to shutdown a channel
                    channel.close().syncUninterruptibly()
                    Thread.yield()
                }
            }

            // we have to clear the shutdown list. (
            shutdownChannelList.clear()
        }
    }

    // shutdown all event loops associated
    fun shutdownEventLoops() {
        // we want to WAIT until after the event executors have completed shutting down.
        val shutdownThreadList: MutableList<Future<*>> = LinkedList()
        var loopGroups: MutableList<EventLoopGroup>
        synchronized(eventLoopGroups) {
            loopGroups = ArrayList(eventLoopGroups.size)
            loopGroups.addAll(eventLoopGroups)
        }
        for (loopGroup in loopGroups) {
            val future = loopGroup.shutdownGracefully(
                maxShutdownWaitTimeInMilliSeconds / 10,
                maxShutdownWaitTimeInMilliSeconds,
                TimeUnit.MILLISECONDS
            )
            shutdownThreadList.add(future)
            Thread.yield()
        }

        // now wait for them to finish!
        // It can take a few seconds to shut down the executor. This will affect unit testing, where connections are quickly created/stopped
        for (f in shutdownThreadList) {
            try {
                f.await(maxShutdownWaitTimeInMilliSeconds)
            } catch (ignored: InterruptedException) {
            }
            Thread.yield()
        }
    }

    protected fun stopWithErrorMessage(logger: Logger, errorMessage: String, throwable: Throwable?): String {
        if (logger.isDebugEnabled && throwable != null) {
            // extra info if debug is enabled
            logger.error(errorMessage, throwable.cause)
        } else {
            logger.error(errorMessage)
        }
        stop()
        return errorMessage
    }

    /**
     * Starts the shutdown process during JVM shutdown, if necessary.
     *
     * By default, we always can shutdown via the JVM shutdown hook.
     */
    protected fun shouldShutdownHookRun(): Boolean {
        return true
    }

    /**
     * Check to see if the current thread is running from it's OWN thread, or from Netty... This is used to prevent deadlocks.
     *
     * @return true if the specified thread is as Netty thread, false if it's own thread.
     */
    protected fun isInEventLoop(thread: Thread?): Boolean {
        for (loopGroup in eventLoopGroups) {
            for (next in loopGroup) {
                if (next.inEventLoop(thread)) {
                    return true
                }
            }
        }
        return false
    }

    /**
     * Safely closes all associated resources/threads/connections.
     *
     *
     * If we want to WAIT for this endpoint to shutdown, we must explicitly call waitForShutdown()
     *
     *
     * Override stopExtraActions() if you want to provide extra behavior while stopping the endpoint
     */
    fun stop() {
        // only permit us to "stop" once!
        if (!stopCalled.compareAndSet(false, true)) {
            return
        }

        // check to make sure we are in our OWN thread, otherwise, this thread will never exit -- because it will wait indefinitely
        // for itself to finish (since it blocks itself).
        // This occurs when calling stop from within a listener callback.
        val currentThread = Thread.currentThread()
        val threadName = currentThread.name
        val isShutdownThread = threadName != shutdownHookName && threadName != stopTreadName

        // used to check the event groups to see if we are running from one of them. NOW we force to
        // ALWAYS shutdown inside a NEW thread
        if (!isShutdownThread || !isInEventLoop(currentThread)) {
            stopInThread()
        } else {
            val thread = Thread { stopInThread() }
            thread.isDaemon = false
            thread.name = stopTreadName
            thread.start()
        }
    }

    /**
     * Extra EXTERNAL actions to perform when stopping this endpoint.
     */
    protected open fun stopExtraActions() {}

    /**
     * Actions that happen by the endpoint before the channels are shutdown
     */
    protected fun shutdownChannelsPre() {}

    /**
     * Actions that happen by the endpoint before any extra actions are run.
     */
    protected fun stopExtraActionsInternal() {}

    // This actually does the "stopping", since there is some logic to making sure we don't deadlock, this is important
    private fun stopInThread() {
        // make sure we are not trying to stop during a startup procedure.
        // This will wait until we have finished starting up/shutting down.
        synchronized(shutdownInProgress) {
            shutdownChannelsPre()
            shutdownAllChannels()
            shutdownEventLoops()
            logger.info("Stopping endpoint.")

            // there is no need to call "stop" again if we close the connection.
            // however, if this is called WHILE from the shutdown hook, blammo! problems!

            // Also, you can call client/server.stop from another thread, which is run when the JVM is shutting down
            // (as there is nothing left to do), and also have problems.
            if (Thread.currentThread().name != shutdownHookName) {
                try {
                    Runtime.getRuntime().removeShutdownHook(shutdownHook)
                } catch (e: Exception) {
                    // ignore
                }
            }
            stopExtraActionsInternal()

            // when the eventloop closes, the associated selectors are ALSO closed!
            stopExtraActions()
            isShutdown = true
        }

        // tell the blocked "bind" method that it may continue (and exit)
        blockUntilDone.countDown()
    }

    /**
     * Blocks the current thread until the endpoint has been stopped. If the endpoint is already stopped, this do nothing.
     */
    fun waitForShutdown() {
        // we now BLOCK until the stop method is called.
        try {
            blockUntilDone.await()
        } catch (e: InterruptedException) {
            logger.error("Thread interrupted while waiting for stop!")
        }
    }

    /**
     * @return true if we have already shutdown, false otherwise
     */
    fun isShutdown(): Boolean {
        synchronized(shutdownInProgress) { return isShutdown }
    }

    override fun toString(): String {
        return "EndPoint [" + name + "]"
    }

    val name: String
        get() = type.simpleName
}
