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
package dorkbox.dns.dns.records

import dorkbox.dns.dns.Compression
import dorkbox.dns.dns.DnsInput
import dorkbox.dns.dns.DnsOutput
import dorkbox.dns.dns.Name
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.exceptions.WireParseException
import dorkbox.dns.dns.utils.Tokenizer
import java.io.IOException
import java.text.DecimalFormat
import java.text.NumberFormat

/**
 * Location - describes the physical location of hosts, networks, subnets.
 *
 * @author Brian Wellington
 */
class LOCRecord : DnsRecord {
    private var size: Long = 0
    private var hPrecision: Long = 0
    private var vPrecision: Long = 0
    private var latitude: Long = 0
    private var longitude: Long = 0
    private var altitude: Long = 0

    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = LOCRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        val version: Int
        version = `in`.readU8()
        if (version != 0) {
            throw WireParseException("Invalid LOC version")
        }

        size = parseLOCformat(`in`.readU8())
        hPrecision = parseLOCformat(`in`.readU8())
        vPrecision = parseLOCformat(`in`.readU8())
        latitude = `in`.readU32()
        longitude = `in`.readU32()
        altitude = `in`.readU32()
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeU8(0) /* version */
        out.writeU8(toLOCformat(size))
        out.writeU8(toLOCformat(hPrecision))
        out.writeU8(toLOCformat(vPrecision))
        out.writeU32(latitude)
        out.writeU32(longitude)
        out.writeU32(altitude)
    }

    /**
     * Convert to a String
     */
    override fun rrToString(sb: StringBuilder) {
        /* Latitude */
        sb.append(positionToString(latitude, 'N', 'S'))
        sb.append(" ")

        /* Latitude */sb.append(positionToString(longitude, 'E', 'W'))
        sb.append(" ")

        /* Altitude */renderFixedPoint(sb, w2, altitude - 10000000, 100)
        sb.append("m ")

        /* Size */renderFixedPoint(sb, w2, size, 100)
        sb.append("m ")

        /* Horizontal precision */renderFixedPoint(sb, w2, hPrecision, 100)
        sb.append("m ")

        /* Vertical precision */renderFixedPoint(sb, w2, vPrecision, 100)
        sb.append("m")
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        latitude = parsePosition(st, "latitude")
        longitude = parsePosition(st, "longitude")
        altitude = parseDouble(st, "altitude", true, -10000000, 4284967295L, 0) + 10000000
        size = parseDouble(st, "size", false, 0, 9000000000L, 100)
        hPrecision = parseDouble(st, "horizontal precision", false, 0, 9000000000L, 1000000)
        vPrecision = parseDouble(st, "vertical precision", false, 0, 9000000000L, 1000)
    }

    @Throws(IOException::class)
    private fun parsePosition(st: Tokenizer, type: String): Long {
        val isLatitude = type == "latitude"
        var deg = 0
        var min = 0
        var sec = 0.0
        var value: Long
        var s: String
        deg = st.getUInt16()
        if (deg > 180 || deg > 90 && isLatitude) {
            throw st.exception("Invalid LOC $type degrees")
        }
        s = st.getString()
        try {
            min = s.toInt()
            if (min < 0 || min > 59) {
                throw st.exception("Invalid LOC $type minutes")
            }
            s = st.getString()
            sec = parseFixedPoint(s)
            if (sec < 0 || sec >= 60) {
                throw st.exception("Invalid LOC $type seconds")
            }
            s = st.getString()
        } catch (e: NumberFormatException) {
        }
        if (s.length != 1) {
            throw st.exception("Invalid LOC $type")
        }
        value = (1000 * (sec + 60L * (min + 60L * deg))).toLong()
        val c = s[0].uppercaseChar()
        if (isLatitude && c == 'S' || !isLatitude && c == 'W') {
            value = -value
        } else if ((isLatitude && c != 'N' || !isLatitude) && c != 'E') {
            throw st.exception("Invalid LOC $type")
        }
        value += 1L shl 31
        return value
    }


    private fun parseFixedPoint(s: String?): Double {


        return if (s!!.matches(regex)) {
            s.toInt().toDouble()
        } else {
            if (s.matches(regex1)) {
                val parts = s.split(regex2).dropLastWhile { it.isEmpty() }.toTypedArray()
                val value = parts[0].toInt().toDouble()
                var fraction = parts[1].toInt().toDouble()
                if (value < 0) {
                    fraction *= -1.0
                }
                val digits = parts[1].length
                value + fraction / Math.pow(10.0, digits.toDouble())
            } else {
                throw NumberFormatException()
            }
        }
    }

    @Throws(IOException::class)
    private fun parseDouble(st: Tokenizer, type: String, required: Boolean, min: Long, max: Long, defaultValue: Long): Long {
        val token = st.get()
        if (token.isEOL) {
            if (required) {
                throw st.exception("Invalid LOC $type")
            }
            st.unget()
            return defaultValue
        }
        var s = token.value
        if (s!!.length > 1 && s[s.length - 1] == 'm') {
            s = s.substring(0, s.length - 1)
        }
        return try {
            val value = (100 * parseFixedPoint(s)).toLong()
            if (value < min || value > max) {
                throw st.exception("Invalid LOC $type")
            }
            value
        } catch (e: NumberFormatException) {
            throw st.exception("Invalid LOC $type")
        }
    }

    private fun positionToString(value: Long, pos: Char, neg: Char): String {
        val sb = StringBuilder()
        val direction: Char
        var temp = value - (1L shl 31)
        if (temp < 0) {
            temp = -temp
            direction = neg
        } else {
            direction = pos
        }
        sb.append(temp / (3600 * 1000)) /* degrees */
        temp = temp % (3600 * 1000)
        sb.append(" ")
        sb.append(temp / (60 * 1000)) /* minutes */
        temp = temp % (60 * 1000)
        sb.append(" ")
        renderFixedPoint(sb, w3, temp, 1000) /* seconds */
        sb.append(" ")
        sb.append(direction)
        return sb.toString()
    }

    private fun renderFixedPoint(sb: StringBuilder, formatter: NumberFormat?, value: Long, divisor: Long) {
        var value = value
        sb.append(value / divisor)
        value %= divisor
        if (value != 0L) {
            sb.append(".")
            sb.append(formatter!!.format(value))
        }
    }

    private fun toLOCformat(l: Long): Int {
        var l = l
        var exp: Byte = 0
        while (l > 9) {
            exp++
            l /= 10
        }
        return ((l shl 4) + exp).toInt()
    }

    /**
     * Creates an LOC Record from the given data
     *
     * @param latitude The latitude of the center of the sphere
     * @param longitude The longitude of the center of the sphere
     * @param altitude The altitude of the center of the sphere, in m
     * @param size The diameter of a sphere enclosing the described entity, in m.
     * @param hPrecision The horizontal precision of the data, in m.
     * @param vPrecision The vertical precision of the data, in m.
     */
    constructor(
        name: Name?,
        dclass: Int,
        ttl: Long,
        latitude: Double,
        longitude: Double,
        altitude: Double,
        size: Double,
        hPrecision: Double,
        vPrecision: Double
    ) : super(name!!, DnsRecordType.LOC, dclass, ttl) {
        this.latitude = (latitude * 3600 * 1000 + (1L shl 31)).toLong()
        this.longitude = (longitude * 3600 * 1000 + (1L shl 31)).toLong()
        this.altitude = ((altitude + 100000) * 100).toLong()
        this.size = (size * 100).toLong()
        this.hPrecision = (hPrecision * 100).toLong()
        this.vPrecision = (vPrecision * 100).toLong()
    }

    /**
     * Returns the latitude
     */
    fun getLatitude(): Double {
        return (latitude - (1L shl 31)).toDouble() / (3600 * 1000)
    }

    /**
     * Returns the longitude
     */
    fun getLongitude(): Double {
        return (longitude - (1L shl 31)).toDouble() / (3600 * 1000)
    }

    /**
     * Returns the altitude
     */
    fun getAltitude(): Double {
        return (altitude - 10000000).toDouble() / 100
    }

    /**
     * Returns the diameter of the enclosing sphere
     */
    fun getSize(): Double {
        return size.toDouble() / 100
    }

    /**
     * Returns the horizontal precision
     */
    fun getHPrecision(): Double {
        return hPrecision.toDouble() / 100
    }

    /**
     * Returns the horizontal precision
     */
    fun getVPrecision(): Double {
        return vPrecision.toDouble() / 100
    }

    companion object {
        private const val serialVersionUID = 9058224788126750409L
        private val w2 = DecimalFormat()
        private val w3 = DecimalFormat()

        val regex = "^-?\\d+$".toRegex()
        val regex1 = "^-?\\d+\\.\\d*$".toRegex()
        val regex2 = "\\.".toRegex()

        init {
            w2.minimumIntegerDigits = 2
            w3.minimumIntegerDigits = 3
        }

        @Throws(WireParseException::class)
        private fun parseLOCformat(b: Int): Long {
            var out = (b shr 4).toLong()
            var exp = b and 0xF
            if (out > 9 || exp > 9) {
                throw WireParseException("Invalid LOC Encoding")
            }
            while (exp-- > 0) {
                out *= 10
            }
            return out
        }
    }
}
