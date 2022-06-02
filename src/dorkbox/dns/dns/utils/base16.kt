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

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * Routines for converting between Strings of hex-encoded data and arrays of
 * binary data.  This is not actually used by DNS.
 *
 * @author Brian Wellington
 */

public
class base16 {

    private static final String Base16 = "0123456789ABCDEF";

    private
    base16() {}

    /**
     * Convert binary data to a hex-encoded String
     *
     * @param b An array containing binary data
     *
     * @return A String containing the encoded data
     */
    public static
    String toString(byte[] b) {
        ByteArrayOutputStream os = new ByteArrayOutputStream();

        for (int i = 0; i < b.length; i++) {
            short value = (short) (b[i] & 0xFF);
            byte high = (byte) (value >> 4);
            byte low = (byte) (value & 0xF);
            os.write(Base16.charAt(high));
            os.write(Base16.charAt(low));
        }
        return new String(os.toByteArray());
    }

    /**
     * Convert a hex-encoded String to binary data
     *
     * @param str A String containing the encoded data
     *
     * @return An array containing the binary data, or null if the string is invalid
     */
    public static
    byte[] fromString(String str) {
        ByteArrayOutputStream bs = new ByteArrayOutputStream();
        byte[] raw = str.getBytes();
        for (int i = 0; i < raw.length; i++) {
            if (!Character.isWhitespace((char) raw[i])) {
                bs.write(raw[i]);
            }
        }
        byte[] in = bs.toByteArray();
        if (in.length % 2 != 0) {
            return null;
        }

        bs.reset();
        DataOutputStream ds = new DataOutputStream(bs);

        for (int i = 0; i < in.length; i += 2) {
            byte high = (byte) Base16.indexOf(Character.toUpperCase((char) in[i]));
            byte low = (byte) Base16.indexOf(Character.toUpperCase((char) in[i + 1]));
            try {
                ds.writeByte((high << 4) + low);
            } catch (IOException e) {
            }
        }
        return bs.toByteArray();
    }

}
