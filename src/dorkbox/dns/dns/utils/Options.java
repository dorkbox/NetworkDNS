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

package dorkbox.dns.dns.utils;

import java.util.StringTokenizer;

import dorkbox.collections.ObjectMap;

/**
 * Boolean options:<BR>
 * bindttl - Print TTLs in BIND format<BR>
 * multiline - Print records in multiline format<BR>
 * noprintin - Don't print the class of a record if it's IN<BR>
 * verbose - Turn on general debugging statements<BR>
 * verbosemsg - Print all messages sent or received by SimpleResolver<BR>
 * verbosecompression - Print messages related to name compression<BR>
 * verbosesec - Print messages related to signature verification<BR>
 * verbosecache - Print messages related to cache lookups<BR>
 * <BR>
 * Valued options:<BR>
 * tsigfudge=n - Sets the default TSIG fudge value (in seconds)<BR>
 * sig0validity=n - Sets the default SIG(0) validity period (in seconds)<BR>
 *
 * @author Brian Wellington
 */

public final
class Options {

    private static ObjectMap<String, Object> table;

    static {
        try {
            refresh();
        } catch (SecurityException ignored) {
        }
    }

    private
    Options() {}

    public static
    void refresh() {
        String s = System.getProperty("dnsjava.options");
        if (s != null) {
            StringTokenizer st = new StringTokenizer(s, ",");
            while (st.hasMoreTokens()) {
                String token = st.nextToken();
                int index = token.indexOf('=');
                if (index == -1) {
                    set(token);
                }
                else {
                    String option = token.substring(0, index);
                    String value = token.substring(index + 1);
                    set(option, value);
                }
            }
        }
    }

    /**
     * Sets an option to "true"
     */
    public static
    void set(String option) {
        if (table == null) {
            table = new ObjectMap<String, Object>();
        }

        table.put(option.toLowerCase(), "true");
    }

    /**
     * Sets an option to the the supplied value
     */
    public static
    void set(String option, String value) {
        if (table == null) {
            table = new ObjectMap<String, Object>();
        }
        table.put(option.toLowerCase(), value.toLowerCase());
    }

    /**
     * Clears all defined options
     */
    public static
    void clear() {
        table = null;
    }

    /**
     * Removes an option
     */
    public static
    void unset(String option) {
        if (table == null) {
            return;
        }
        table.remove(option.toLowerCase());
    }

    /**
     * Checks if an option is defined
     */
    public static
    boolean check(String option) {
        if (table == null) {
            return false;
        }

        return (table.get(option.toLowerCase()) != null);
    }

    /**
     * Returns the value of an option as an integer, or -1 if not defined.
     */
    public static
    int intValue(String option) {
        String s = value(option);
        if (s != null) {
            try {
                int val = Integer.parseInt(s);
                if (val > 0) {
                    return (val);
                }
            } catch (NumberFormatException ignored) {
            }
        }

        return -1;
    }

    /**
     * Returns the value of an option
     */
    public static
    String value(String option) {
        if (table == null) {
            return null;
        }

        return ((String) table.get(option.toLowerCase()));
    }
}
