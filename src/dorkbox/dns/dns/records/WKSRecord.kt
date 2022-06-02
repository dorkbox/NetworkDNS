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
import dorkbox.dns.dns.Mnemonic
import dorkbox.dns.dns.Name
import dorkbox.dns.dns.constants.DnsRecordType
import dorkbox.dns.dns.utils.Tokenizer
import dorkbox.netUtil.IPv4.isFamily
import dorkbox.netUtil.IPv4.toBytesOrNull
import dorkbox.netUtil.IPv4.toString
import java.io.IOException
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.*

/**
 * Well Known Services - Lists services offered by this host.
 *
 * @author Brian Wellington
 */
class WKSRecord : DnsRecord {
    private lateinit var address: ByteArray

    /**
     * Returns the IP protocol.
     */
    var protocol = 0
        private set

    /**
     * Returns the services provided by the host on the specified address.
     */
    lateinit var services: IntArray
        private set

    object Protocol {
        /**
         * Internet Control DnsMessage
         */
        const val ICMP = 1

        /**
         * Internet Group Management
         */
        const val IGMP = 2

        /**
         * Gateway-to-Gateway
         */
        const val GGP = 3

        /**
         * Stream
         */
        const val ST = 5

        /**
         * Transmission Control
         */
        const val TCP = 6

        /**
         * UCL
         */
        const val UCL = 7

        /**
         * Exterior Gateway Protocol
         */
        const val EGP = 8

        /**
         * any private interior gateway
         */
        const val IGP = 9

        /**
         * BBN RCC Monitoring
         */
        const val BBN_RCC_MON = 10

        /**
         * Network Voice Protocol
         */
        const val NVP_II = 11

        /**
         * PUP
         */
        const val PUP = 12

        /**
         * ARGUS
         */
        const val ARGUS = 13

        /**
         * EMCON
         */
        const val EMCON = 14

        /**
         * Cross Net Debugger
         */
        const val XNET = 15

        /**
         * Chaos
         */
        const val CHAOS = 16

        /**
         * User Datagram
         */
        const val UDP = 17

        /**
         * Multiplexing
         */
        const val MUX = 18

        /**
         * DCN Measurement Subsystems
         */
        const val DCN_MEAS = 19

        /**
         * Host Monitoring
         */
        const val HMP = 20

        /**
         * Packet Radio Measurement
         */
        const val PRM = 21

        /**
         * XEROX NS IDP
         */
        const val XNS_IDP = 22

        /**
         * Trunk-1
         */
        const val TRUNK_1 = 23

        /**
         * Trunk-2
         */
        const val TRUNK_2 = 24

        /**
         * Leaf-1
         */
        const val LEAF_1 = 25

        /**
         * Leaf-2
         */
        const val LEAF_2 = 26

        /**
         * Reliable Data Protocol
         */
        const val RDP = 27

        /**
         * Internet Reliable Transaction
         */
        const val IRTP = 28

        /**
         * ISO Transport Protocol Class 4
         */
        const val ISO_TP4 = 29

        /**
         * Bulk Data Transfer Protocol
         */
        const val NETBLT = 30

        /**
         * MFE Network Services Protocol
         */
        const val MFE_NSP = 31

        /**
         * MERIT Internodal Protocol
         */
        const val MERIT_INP = 32

        /**
         * Sequential Exchange Protocol
         */
        const val SEP = 33

        /**
         * CFTP
         */
        const val CFTP = 62

        /**
         * SATNET and Backroom EXPAK
         */
        const val SAT_EXPAK = 64

        /**
         * MIT Subnet Support
         */
        const val MIT_SUBNET = 65

        /**
         * MIT Remote Virtual Disk Protocol
         */
        const val RVD = 66

        /**
         * Internet Pluribus Packet Core
         */
        const val IPPC = 67

        /**
         * SATNET Monitoring
         */
        const val SAT_MON = 69

        /**
         * Internet Packet Core Utility
         */
        const val IPCV = 71

        /**
         * Backroom SATNET Monitoring
         */
        const val BR_SAT_MON = 76

        /**
         * WIDEBAND Monitoring
         */
        const val WB_MON = 78

        /**
         * WIDEBAND EXPAK
         */
        const val WB_EXPAK = 79
        private val protocols = Mnemonic("IP protocol", Mnemonic.CASE_LOWER)

        init {
            protocols.setMaximum(0xFF)
            protocols.setNumericAllowed(true)
            protocols.add(ICMP, "icmp")
            protocols.add(IGMP, "igmp")
            protocols.add(GGP, "ggp")
            protocols.add(ST, "st")
            protocols.add(TCP, "tcp")
            protocols.add(UCL, "ucl")
            protocols.add(EGP, "egp")
            protocols.add(IGP, "igp")
            protocols.add(BBN_RCC_MON, "bbn-rcc-mon")
            protocols.add(NVP_II, "nvp-ii")
            protocols.add(PUP, "pup")
            protocols.add(ARGUS, "argus")
            protocols.add(EMCON, "emcon")
            protocols.add(XNET, "xnet")
            protocols.add(CHAOS, "chaos")
            protocols.add(UDP, "udp")
            protocols.add(MUX, "mux")
            protocols.add(DCN_MEAS, "dcn-meas")
            protocols.add(HMP, "hmp")
            protocols.add(PRM, "prm")
            protocols.add(XNS_IDP, "xns-idp")
            protocols.add(TRUNK_1, "trunk-1")
            protocols.add(TRUNK_2, "trunk-2")
            protocols.add(LEAF_1, "leaf-1")
            protocols.add(LEAF_2, "leaf-2")
            protocols.add(RDP, "rdp")
            protocols.add(IRTP, "irtp")
            protocols.add(ISO_TP4, "iso-tp4")
            protocols.add(NETBLT, "netblt")
            protocols.add(MFE_NSP, "mfe-nsp")
            protocols.add(MERIT_INP, "merit-inp")
            protocols.add(SEP, "sep")
            protocols.add(CFTP, "cftp")
            protocols.add(SAT_EXPAK, "sat-expak")
            protocols.add(MIT_SUBNET, "mit-subnet")
            protocols.add(RVD, "rvd")
            protocols.add(IPPC, "ippc")
            protocols.add(SAT_MON, "sat-mon")
            protocols.add(IPCV, "ipcv")
            protocols.add(BR_SAT_MON, "br-sat-mon")
            protocols.add(WB_MON, "wb-mon")
            protocols.add(WB_EXPAK, "wb-expak")
        }

        /**
         * Converts an IP protocol value into its textual representation
         */
        fun string(type: Int): String {
            return protocols.getText(type)
        }

        /**
         * Converts a textual representation of an IP protocol into its
         * numeric code.  Integers in the range 0..255 are also accepted.
         *
         * @param s The textual representation of the protocol
         *
         * @return The protocol code, or -1 on error.
         */
        fun value(s: String?): Int {
            return protocols.getValue(s!!)
        }
    }

    object Service {
        /**
         * Remote Job Entry
         */
        const val RJE = 5

        /**
         * Echo
         */
        const val ECHO = 7

        /**
         * Discard
         */
        const val DISCARD = 9

        /**
         * Active Users
         */
        const val USERS = 11

        /**
         * Daytime
         */
        const val DAYTIME = 13

        /**
         * Quote of the Day
         */
        const val QUOTE = 17

        /**
         * Character Generator
         */
        const val CHARGEN = 19

        /**
         * File Transfer [Default Data]
         */
        const val FTP_DATA = 20

        /**
         * File Transfer [Control]
         */
        const val FTP = 21

        /**
         * Telnet
         */
        const val TELNET = 23

        /**
         * Simple Mail Transfer
         */
        const val SMTP = 25

        /**
         * NSW User System FE
         */
        const val NSW_FE = 27

        /**
         * MSG ICP
         */
        const val MSG_ICP = 29

        /**
         * MSG Authentication
         */
        const val MSG_AUTH = 31

        /**
         * Display Support Protocol
         */
        const val DSP = 33

        /**
         * Time
         */
        const val TIME = 37

        /**
         * Resource Location Protocol
         */
        const val RLP = 39

        /**
         * Graphics
         */
        const val GRAPHICS = 41

        /**
         * Host Name Server
         */
        const val NAMESERVER = 42

        /**
         * Who Is
         */
        const val NICNAME = 43

        /**
         * MPM FLAGS Protocol
         */
        const val MPM_FLAGS = 44

        /**
         * DnsMessage Processing Module [recv]
         */
        const val MPM = 45

        /**
         * MPM [default send]
         */
        const val MPM_SND = 46

        /**
         * NI FTP
         */
        const val NI_FTP = 47

        /**
         * Login Host Protocol
         */
        const val LOGIN = 49

        /**
         * IMP Logical Address Maintenance
         */
        const val LA_MAINT = 51

        /**
         * Domain Name Server
         */
        const val DOMAIN = 53

        /**
         * ISI Graphics Language
         */
        const val ISI_GL = 55

        /**
         * NI MAIL
         */
        const val NI_MAIL = 61

        /**
         * VIA Systems - FTP
         */
        const val VIA_FTP = 63

        /**
         * TACACS-Database Service
         */
        const val TACACS_DS = 65

        /**
         * Bootstrap Protocol Server
         */
        const val BOOTPS = 67

        /**
         * Bootstrap Protocol Client
         */
        const val BOOTPC = 68

        /**
         * Trivial File Transfer
         */
        const val TFTP = 69

        /**
         * Remote Job Service
         */
        const val NETRJS_1 = 71

        /**
         * Remote Job Service
         */
        const val NETRJS_2 = 72

        /**
         * Remote Job Service
         */
        const val NETRJS_3 = 73

        /**
         * Remote Job Service
         */
        const val NETRJS_4 = 74

        /**
         * Finger
         */
        const val FINGER = 79

        /**
         * HOSTS2 Name Server
         */
        const val HOSTS2_NS = 81

        /**
         * SU/MIT Telnet Gateway
         */
        const val SU_MIT_TG = 89

        /**
         * MIT Dover Spooler
         */
        const val MIT_DOV = 91

        /**
         * Device Control Protocol
         */
        const val DCP = 93

        /**
         * SUPDUP
         */
        const val SUPDUP = 95

        /**
         * Swift Remote Virtual File Protocol
         */
        const val SWIFT_RVF = 97

        /**
         * TAC News
         */
        const val TACNEWS = 98

        /**
         * Metagram Relay
         */
        const val METAGRAM = 99

        /**
         * NIC Host Name Server
         */
        const val HOSTNAME = 101

        /**
         * ISO-TSAP
         */
        const val ISO_TSAP = 102

        /**
         * X400
         */
        const val X400 = 103

        /**
         * X400-SND
         */
        const val X400_SND = 104

        /**
         * Mailbox Name Nameserver
         */
        const val CSNET_NS = 105

        /**
         * Remote Telnet Service
         */
        const val RTELNET = 107

        /**
         * Post Office Protocol - Version 2
         */
        const val POP_2 = 109

        /**
         * SUN Remote Procedure Call
         */
        const val SUNRPC = 111

        /**
         * Authentication Service
         */
        const val AUTH = 113

        /**
         * Simple File Transfer Protocol
         */
        const val SFTP = 115

        /**
         * UUCP Path Service
         */
        const val UUCP_PATH = 117

        /**
         * Network News Transfer Protocol
         */
        const val NNTP = 119

        /**
         * HYDRA Expedited Remote Procedure
         */
        const val ERPC = 121

        /**
         * Network Time Protocol
         */
        const val NTP = 123

        /**
         * Locus PC-Interface Net Map Server
         */
        const val LOCUS_MAP = 125

        /**
         * Locus PC-Interface Conn Server
         */
        const val LOCUS_CON = 127

        /**
         * Password Generator Protocol
         */
        const val PWDGEN = 129

        /**
         * CISCO FNATIVE
         */
        const val CISCO_FNA = 130

        /**
         * CISCO TNATIVE
         */
        const val CISCO_TNA = 131

        /**
         * CISCO SYSMAINT
         */
        const val CISCO_SYS = 132

        /**
         * Statistics Service
         */
        const val STATSRV = 133

        /**
         * INGRES-NET Service
         */
        const val INGRES_NET = 134

        /**
         * Location Service
         */
        const val LOC_SRV = 135

        /**
         * PROFILE Naming System
         */
        const val PROFILE = 136

        /**
         * NETBIOS Name Service
         */
        const val NETBIOS_NS = 137

        /**
         * NETBIOS Datagram Service
         */
        const val NETBIOS_DGM = 138

        /**
         * NETBIOS Session Service
         */
        const val NETBIOS_SSN = 139

        /**
         * EMFIS Data Service
         */
        const val EMFIS_DATA = 140

        /**
         * EMFIS Control Service
         */
        const val EMFIS_CNTL = 141

        /**
         * Britton-Lee IDM
         */
        const val BL_IDM = 142

        /**
         * Survey Measurement
         */
        const val SUR_MEAS = 243

        /**
         * LINK
         */
        const val LINK = 245
        private val services = Mnemonic("TCP/UDP service", Mnemonic.CASE_LOWER)

        init {
            services.setMaximum(0xFFFF)
            services.setNumericAllowed(true)
            services.add(RJE, "rje")
            services.add(ECHO, "echo")
            services.add(DISCARD, "discard")
            services.add(USERS, "users")
            services.add(DAYTIME, "daytime")
            services.add(QUOTE, "quote")
            services.add(CHARGEN, "chargen")
            services.add(FTP_DATA, "ftp-data")
            services.add(FTP, "ftp")
            services.add(TELNET, "telnet")
            services.add(SMTP, "smtp")
            services.add(NSW_FE, "nsw-fe")
            services.add(MSG_ICP, "msg-icp")
            services.add(MSG_AUTH, "msg-auth")
            services.add(DSP, "dsp")
            services.add(TIME, "time")
            services.add(RLP, "rlp")
            services.add(GRAPHICS, "graphics")
            services.add(NAMESERVER, "nameserver")
            services.add(NICNAME, "nicname")
            services.add(MPM_FLAGS, "mpm-flags")
            services.add(MPM, "mpm")
            services.add(MPM_SND, "mpm-snd")
            services.add(NI_FTP, "ni-ftp")
            services.add(LOGIN, "login")
            services.add(LA_MAINT, "la-maint")
            services.add(DOMAIN, "domain")
            services.add(ISI_GL, "isi-gl")
            services.add(NI_MAIL, "ni-mail")
            services.add(VIA_FTP, "via-ftp")
            services.add(TACACS_DS, "tacacs-ds")
            services.add(BOOTPS, "bootps")
            services.add(BOOTPC, "bootpc")
            services.add(TFTP, "tftp")
            services.add(NETRJS_1, "netrjs-1")
            services.add(NETRJS_2, "netrjs-2")
            services.add(NETRJS_3, "netrjs-3")
            services.add(NETRJS_4, "netrjs-4")
            services.add(FINGER, "finger")
            services.add(HOSTS2_NS, "hosts2-ns")
            services.add(SU_MIT_TG, "su-mit-tg")
            services.add(MIT_DOV, "mit-dov")
            services.add(DCP, "dcp")
            services.add(SUPDUP, "supdup")
            services.add(SWIFT_RVF, "swift-rvf")
            services.add(TACNEWS, "tacnews")
            services.add(METAGRAM, "metagram")
            services.add(HOSTNAME, "hostname")
            services.add(ISO_TSAP, "iso-tsap")
            services.add(X400, "x400")
            services.add(X400_SND, "x400-snd")
            services.add(CSNET_NS, "csnet-ns")
            services.add(RTELNET, "rtelnet")
            services.add(POP_2, "pop-2")
            services.add(SUNRPC, "sunrpc")
            services.add(AUTH, "auth")
            services.add(SFTP, "sftp")
            services.add(UUCP_PATH, "uucp-path")
            services.add(NNTP, "nntp")
            services.add(ERPC, "erpc")
            services.add(NTP, "ntp")
            services.add(LOCUS_MAP, "locus-map")
            services.add(LOCUS_CON, "locus-con")
            services.add(PWDGEN, "pwdgen")
            services.add(CISCO_FNA, "cisco-fna")
            services.add(CISCO_TNA, "cisco-tna")
            services.add(CISCO_SYS, "cisco-sys")
            services.add(STATSRV, "statsrv")
            services.add(INGRES_NET, "ingres-net")
            services.add(LOC_SRV, "loc-srv")
            services.add(PROFILE, "profile")
            services.add(NETBIOS_NS, "netbios-ns")
            services.add(NETBIOS_DGM, "netbios-dgm")
            services.add(NETBIOS_SSN, "netbios-ssn")
            services.add(EMFIS_DATA, "emfis-data")
            services.add(EMFIS_CNTL, "emfis-cntl")
            services.add(BL_IDM, "bl-idm")
            services.add(SUR_MEAS, "sur-meas")
            services.add(LINK, "link")
        }

        /**
         * Converts a TCP/UDP service port number into its textual
         * representation.
         */
        fun string(type: Int): String {
            return services.getText(type)
        }

        /**
         * Converts a textual representation of a TCP/UDP service into its
         * port number.  Integers in the range 0..65535 are also accepted.
         *
         * @param s The textual representation of the service.
         *
         * @return The port number, or -1 on error.
         */
        fun value(s: String?): Int {
            return services.getValue(s!!)
        }
    }

    internal constructor() {}

    override val `object`: DnsRecord
        get() = WKSRecord()

    @Throws(IOException::class)
    override fun rrFromWire(`in`: DnsInput) {
        address = `in`.readByteArray(4)
        protocol = `in`.readU8()
        val array = `in`.readByteArray()
        val list: MutableList<Int> = ArrayList()
        for (i in array.indices) {
            for (j in 0..7) {
                val octet = array[i].toInt() and 0xFF
                if (octet and (1 shl 7) - j != 0) {
                    list.add(i * 8 + j)
                }
            }
        }
        services = IntArray(list.size)
        for (i in list.indices) {
            services[i] = list[i]
        }
    }

    override fun rrToWire(out: DnsOutput, c: Compression?, canonical: Boolean) {
        out.writeByteArray(address)
        out.writeU8(protocol)
        val highestPort = services[services.size - 1]
        val array = ByteArray(highestPort / 8 + 1)
        for (port in services) {
            array[port / 8] = (array[port / 8].toInt() or (1 shl 7) - port % 8).toByte()
        }
        out.writeByteArray(array)
    }

    /**
     * Converts rdata to a String
     */
    override fun rrToString(sb: StringBuilder) {
        toString(address, sb)
        sb.append(" ")
        sb.append(protocol)
        for (service in services) {
            sb.append(" ").append(service)
        }
    }

    @Throws(IOException::class)
    override fun rdataFromString(st: Tokenizer, origin: Name?) {
        var s = st.getString()
        val address = toBytesOrNull(s) ?: throw st.exception("invalid address")

        this.address = address

        s = st.getString()
        protocol = Protocol.value(s)
        if (protocol < 0) {
            throw st.exception("Invalid IP protocol: $s")
        }
        val list: MutableList<Int> = ArrayList()
        while (true) {
            val t = st.get()
            if (!t.isString) {
                break
            }
            val service = Service.value(t.value)
            if (service < 0) {
                throw st.exception("Invalid TCP/UDP service: " + t.value)
            }
            list.add(service)
        }
        st.unget()
        services = IntArray(list.size)
        for (i in list.indices) {
            services[i] = list[i]
        }
    }

    /**
     * Creates a WKS Record from the given data
     *
     * @param address The IP address
     * @param protocol The IP protocol number
     * @param services An array of supported services, represented by port number.
     */
    constructor(name: Name, dclass: Int, ttl: Long, address: InetAddress, protocol: Int, services: IntArray) : super(
        name, DnsRecordType.WKS, dclass, ttl
    ) {
        require(isFamily(address)) { "invalid IPv4 address" }

        this.address = address.address
        this.protocol = checkU8("protocol", protocol)

        for (service in services) {
            checkU16("service", service)
        }

        this.services = IntArray(services.size)
        System.arraycopy(services, 0, this.services, 0, services.size)
        Arrays.sort(this.services)
    }

    /**
     * Returns the IP address.
     */
    fun getAddress(): InetAddress? {
        return try {
            InetAddress.getByAddress(address)
        } catch (e: UnknownHostException) {
            null
        }
    }

    companion object {
        private const val serialVersionUID = -9104259763909119805L
    }
}
