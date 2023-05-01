/*
 * Copyright 2023 dorkbox, llc
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
package dorkbox.dns.dns.resolver.lifecycle

import dorkbox.dns.dns.records.DnsMessage
import io.netty.util.internal.ObjectUtil
import io.netty.util.internal.logging.InternalLogLevel
import org.slf4j.Logger
import org.slf4j.LoggerFactory

internal class TraceDnsQueryLifeCycleObserverFactory(
        logger: Logger = DEFAULT_LOGGER,
        level: InternalLogLevel = DEFAULT_LEVEL) : DnsQueryLifecycleObserverFactory {

    companion object {
        private val DEFAULT_LOGGER = LoggerFactory.getLogger(TraceDnsQueryLifeCycleObserverFactory::class.java)
        private val DEFAULT_LEVEL = InternalLogLevel.DEBUG
    }

    private val logger: Logger

    init {
        this.logger = ObjectUtil.checkNotNull(logger, "logger")
    }

    override fun newDnsQueryLifecycleObserver(question: DnsMessage): DnsQueryLifecycleObserver {
        return TraceDnsQueryLifecycleObserver(question, logger)
    }
}
