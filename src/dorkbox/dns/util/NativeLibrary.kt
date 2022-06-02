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

import dorkbox.dns.util.Shutdownable.Companion.enableNativeLibrary
import dorkbox.os.OS.isLinux
import dorkbox.os.OS.isMacOsX
import io.netty.channel.epoll.Epoll
import io.netty.channel.kqueue.KQueue

object NativeLibrary {
    /**
     * @return true if the (possibly) required native libraries have been loaded
     */
    val isAvailable: Boolean
        get() {
            if (!enableNativeLibrary) {
                return false
            }
            if (isLinux) {
                return Epoll.isAvailable()
            } else if (isMacOsX) {
                return KQueue.isAvailable()
            }

            // not Linux/MacOsX
            return false
        }
}
