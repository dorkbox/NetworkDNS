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

package dorkbox.dns.dns.records;

import java.io.IOException;

import dorkbox.dns.dns.Compression;
import dorkbox.dns.dns.DnsInput;
import dorkbox.dns.dns.DnsOutput;
import dorkbox.dns.dns.Name;
import dorkbox.dns.dns.constants.DnsRecordType;
import dorkbox.dns.dns.exceptions.TextParseException;
import dorkbox.dns.dns.exceptions.WireParseException;
import dorkbox.dns.dns.utils.Tokenizer;

/**
 * Geographical Location - describes the physical location of a host.
 *
 * @author Brian Wellington
 */
@Deprecated
public
class GPOSRecord extends DnsRecord {

    private static final long serialVersionUID = -6349714958085750705L;

    private byte[] latitude, longitude, altitude;

    GPOSRecord() {}

    @Override
    DnsRecord getObject() {
        return new GPOSRecord();
    }

    @Override
    void rrFromWire(DnsInput in) throws IOException {
        longitude = in.readCountedString();
        latitude = in.readCountedString();
        altitude = in.readCountedString();
        try {
            validate(getLongitude(), getLatitude());
        } catch (IllegalArgumentException e) {
            throw new WireParseException(e.getMessage());
        }
    }

    @Override
    void rrToWire(DnsOutput out, Compression c, boolean canonical) {
        out.writeCountedString(longitude);
        out.writeCountedString(latitude);
        out.writeCountedString(altitude);
    }

    /**
     * Convert to a String
     */
    @Override
    void rrToString(StringBuilder sb) {
        sb.append(byteArrayToString(longitude, true));
        sb.append(" ");
        sb.append(byteArrayToString(latitude, true));
        sb.append(" ");
        sb.append(byteArrayToString(altitude, true));
    }

    @Override
    void rdataFromString(Tokenizer st, Name origin) throws IOException {
        try {
            longitude = byteArrayFromString(st.getString());
            latitude = byteArrayFromString(st.getString());
            altitude = byteArrayFromString(st.getString());
        } catch (TextParseException e) {
            throw st.exception(e.getMessage());
        }
        try {
            validate(getLongitude(), getLatitude());
        } catch (IllegalArgumentException e) {
            throw new WireParseException(e.getMessage());
        }
    }

    /**
     * Creates an GPOS Record from the given data
     *
     * @param longitude The longitude component of the location.
     * @param latitude The latitude component of the location.
     * @param altitude The altitude component of the location (in meters above sea
     *         level).
     */
    public
    GPOSRecord(Name name, int dclass, long ttl, double longitude, double latitude, double altitude) {
        super(name, DnsRecordType.GPOS, dclass, ttl);
        validate(longitude, latitude);
        this.longitude = Double.toString(longitude).getBytes();
        this.latitude = Double.toString(latitude).getBytes();
        this.altitude = Double.toString(altitude).getBytes();
    }

    private
    void validate(double longitude, double latitude) throws IllegalArgumentException {
        if (longitude < -90.0 || longitude > 90.0) {
            throw new IllegalArgumentException("illegal longitude " + longitude);
        }
        if (latitude < -180.0 || latitude > 180.0) {
            throw new IllegalArgumentException("illegal latitude " + latitude);
        }
    }

    /**
     * Creates an GPOS Record from the given data
     *
     * @param longitude The longitude component of the location.
     * @param latitude The latitude component of the location.
     * @param altitude The altitude component of the location (in meters above sea
     *         level).
     */
    public
    GPOSRecord(Name name, int dclass, long ttl, String longitude, String latitude, String altitude) {
        super(name, DnsRecordType.GPOS, dclass, ttl);
        try {
            this.longitude = byteArrayFromString(longitude);
            this.latitude = byteArrayFromString(latitude);
            validate(getLongitude(), getLatitude());
            this.altitude = byteArrayFromString(altitude);
        } catch (TextParseException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    /**
     * Returns the longitude as a double
     *
     * @throws NumberFormatException The string does not contain a valid numeric
     *         value.
     */
    public
    double getLongitude() {
        return Double.parseDouble(getLongitudeString());
    }

    /**
     * Returns the longitude as a string
     */
    public
    String getLongitudeString() {
        return byteArrayToString(longitude, false);
    }

    /**
     * Returns the latitude as a double
     *
     * @throws NumberFormatException The string does not contain a valid numeric
     *         value.
     */
    public
    double getLatitude() {
        return Double.parseDouble(getLatitudeString());
    }

    /**
     * Returns the latitude as a string
     */
    public
    String getLatitudeString() {
        return byteArrayToString(latitude, false);
    }

    /**
     * Returns the altitude as a double
     *
     * @throws NumberFormatException The string does not contain a valid numeric
     *         value.
     */
    public
    double getAltitude() {
        return Double.parseDouble(getAltitudeString());
    }

    /**
     * Returns the altitude as a string
     */
    public
    String getAltitudeString() {
        return byteArrayToString(altitude, false);
    }

}
