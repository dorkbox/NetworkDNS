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
package dorkbox.dns.dns.utils

import dorkbox.collections.ObjectMap
import java.util.*

/**
 * Boolean options:<BR></BR>
 * bindttl - Print TTLs in BIND format<BR></BR>
 * multiline - Print records in multiline format<BR></BR>
 * noprintin - Don't print the class of a record if it's IN<BR></BR>
 * verbose - Turn on general debugging statements<BR></BR>
 * verbosemsg - Print all messages sent or received by SimpleResolver<BR></BR>
 * verbosecompression - Print messages related to name compression<BR></BR>
 * verbosesec - Print messages related to signature verification<BR></BR>
 * verbosecache - Print messages related to cache lookups<BR></BR>
 * <BR></BR>
 * Valued options:<BR></BR>
 * tsigfudge=n - Sets the default TSIG fudge value (in seconds)<BR></BR>
 * sig0validity=n - Sets the default SIG(0) validity period (in seconds)<BR></BR>
 *
 * @author Brian Wellington
 */
object Options {
    private var table: ObjectMap<String, Any?>? = null

    init {
        try {
            refresh()
        } catch (ignored: SecurityException) {
        }
    }

    fun refresh() {
        val s = System.getProperty("dnsjava.options")
        if (s != null) {
            val st = StringTokenizer(s, ",")
            while (st.hasMoreTokens()) {
                val token = st.nextToken()
                val index = token.indexOf('=')
                if (index == -1) {
                    set(token)
                } else {
                    val option = token.substring(0, index)
                    val value = token.substring(index + 1)
                    Options[option] = value
                }
            }
        }
    }

    /**
     * Sets an option to "true"
     */
    fun set(option: String) {
        if (table == null) {
            table = ObjectMap()
        }
        table!!.put(option.lowercase(Locale.getDefault()), "true")
    }

    /**
     * Sets an option to the the supplied value
     */
    operator fun set(option: String, value: String) {
        if (table == null) {
            table = ObjectMap()
        }
        table!!.put(option.lowercase(Locale.getDefault()), value.lowercase(Locale.getDefault()))
    }

    /**
     * Clears all defined options
     */
    fun clear() {
        table = null
    }

    /**
     * Removes an option
     */
    fun unset(option: String) {
        if (table == null) {
            return
        }
        table!!.remove(option.lowercase(Locale.getDefault()))
    }

    /**
     * Checks if an option is defined
     */
    fun check(option: String): Boolean {
        return if (table == null) {
            false
        } else table!![option.lowercase(Locale.getDefault())] != null
    }

    /**
     * Returns the value of an option as an integer, or -1 if not defined.
     */
    fun intValue(option: String): Int {
        val s = value(option)
        if (s != null) {
            try {
                val `val` = s.toInt()
                if (`val` > 0) {
                    return `val`
                }
            } catch (ignored: NumberFormatException) {
            }
        }
        return -1
    }

    /**
     * Returns the value of an option
     */
    fun value(option: String): String? {
        return if (table == null) {
            null
        } else table!![option.lowercase(Locale.getDefault())] as String?
    }
}
