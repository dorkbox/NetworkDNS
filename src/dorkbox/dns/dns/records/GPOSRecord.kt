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
import dorkbox.dns.dns.exceptions.TextParseException
import dorkbox.dns.dns.exceptions.WireParseException
import dorkbox.dns.dns.utils.Tokenizer
import java.io.IOException

/**
 * Geographical Location - describes the physical location of a host.
 *
 * @author Brian Wellington
 */
@Deprecated("")
class GPOSRecord : DnsRecord {
    private lateinit var latitude: ByteArray
    private lateinit var longitude: ByteArray
    private lateinit var altitude: ByteArray

    internal constructor() {}

    override val dnsRecord: DnsRecord
        get() = GPOSRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        longitude = `in`.readCountedString()
        latitude = `in`.readCountedString()
        altitude = `in`.readCountedString()
        try {
            validate(getLongitude(), getLatitude())
        } catch (e: IllegalArgumentException) {
            throw WireParseException(e.message!!)
        }
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeCountedString(longitude)
        out.writeCountedString(latitude)
        out.writeCountedString(altitude)
    }

    /**
     * Convert to a String
     */
    override fun rrToString(sb: StringBuilder) {
        sb.append(byteArrayToString(longitude, true))
        sb.append(" ")
        sb.append(byteArrayToString(latitude, true))
        sb.append(" ")
        sb.append(byteArrayToString(altitude, true))
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        try {
            longitude = byteArrayFromString(st.getString())
            latitude = byteArrayFromString(st.getString())
            altitude = byteArrayFromString(st.getString())
        } catch (e: TextParseException) {
            throw st.exception(e.message ?: "")
        }
        try {
            validate(getLongitude(), getLatitude())
        } catch (e: IllegalArgumentException) {
            throw WireParseException(e.message ?: "")
        }
    }

    /**
     * Creates an GPOS Record from the given data
     *
     * @param longitude The longitude component of the location.
     * @param latitude The latitude component of the location.
     * @param altitude The altitude component of the location (in meters above sea
     * level).
     */
    constructor(name: Name?, dclass: Int, ttl: Long, longitude: Double, latitude: Double, altitude: Double) : super(
        name!!, DnsRecordType.GPOS, dclass, ttl
    ) {
        validate(longitude, latitude)
        this.longitude = java.lang.Double.toString(longitude).toByteArray()
        this.latitude = java.lang.Double.toString(latitude).toByteArray()
        this.altitude = java.lang.Double.toString(altitude).toByteArray()
    }

    @Throws(IllegalArgumentException::class)
    private fun validate(longitude: Double, latitude: Double) {
        require(!(longitude < -90.0 || longitude > 90.0)) { "illegal longitude $longitude" }
        require(!(latitude < -180.0 || latitude > 180.0)) { "illegal latitude $latitude" }
    }

    /**
     * Creates an GPOS Record from the given data
     *
     * @param longitude The longitude component of the location.
     * @param latitude The latitude component of the location.
     * @param altitude The altitude component of the location (in meters above sea
     * level).
     */
    constructor(name: Name?, dclass: Int, ttl: Long, longitude: String?, latitude: String?, altitude: String?) : super(
        name!!, DnsRecordType.GPOS, dclass, ttl
    ) {
        try {
            this.longitude = byteArrayFromString(longitude!!)
            this.latitude = byteArrayFromString(latitude!!)
            validate(getLongitude(), getLatitude())
            this.altitude = byteArrayFromString(altitude!!)
        } catch (e: TextParseException) {
            throw IllegalArgumentException(e.message)
        }
    }

    /**
     * Returns the longitude as a double
     *
     * @throws NumberFormatException The string does not contain a valid numeric
     * value.
     */
    fun getLongitude(): Double {
        return longitudeString.toDouble()
    }

    /**
     * Returns the longitude as a string
     */
    val longitudeString: String
        get() = byteArrayToString(longitude, false)

    /**
     * Returns the latitude as a double
     *
     * @throws NumberFormatException The string does not contain a valid numeric
     * value.
     */
    fun getLatitude(): Double {
        return latitudeString.toDouble()
    }

    /**
     * Returns the latitude as a string
     */
    val latitudeString: String
        get() = byteArrayToString(latitude, false)

    /**
     * Returns the altitude as a double
     *
     * @throws NumberFormatException The string does not contain a valid numeric
     * value.
     */
    fun getAltitude(): Double {
        return altitudeString.toDouble()
    }

    /**
     * Returns the altitude as a string
     */
    val altitudeString: String
        get() = byteArrayToString(altitude, false)

    companion object {
        private const val serialVersionUID = -6349714958085750705L
    }
}
