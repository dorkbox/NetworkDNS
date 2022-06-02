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

import dorkbox.dns.dns.Name
import dorkbox.dns.dns.exceptions.RelativeNameException
import dorkbox.dns.dns.exceptions.TextParseException
import dorkbox.dns.dns.records.TTL
import dorkbox.netUtil.IPv4
import dorkbox.netUtil.IPv6
import java.io.BufferedInputStream
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream
import java.io.PushbackInputStream
import java.net.InetAddress
import java.net.UnknownHostException
import java.util.*

/**
 * Tokenizer is used to parse DNS records and zones from text format,
 *
 * @author Brian Wellington
 * @author Bob Halley
 */
class Tokenizer(inputStream: InputStream) : AutoCloseable {
    private val `is`: PushbackInputStream
    private var ungottenToken: Boolean
    private var multiline: Int
    private var quoting: Boolean
    private var delimiters: String
    private val current: Token
    private val sb: StringBuilder
    private var wantClose = false
    private var filename: String
    private var line: Int

    class Token {
        /**
         * The type of token.
         */
        var type: Int

        /**
         * The value of the token, or null for tokens without values.
         */
        var value: String?

        init {
            type = -1
            value = null
        }

        operator fun set(type: Int, value: StringBuilder?): Token {
            require(type >= 0)
            this.type = type
            this.value = value?.toString()
            return this
        }

        /**
         * Converts the token to a string containing a representation useful
         * for debugging.
         */
        override fun toString(): String {
            return when (type) {
                EOF -> "<eof>"
                EOL -> "<eol>"
                WHITESPACE -> "<whitespace>"
                IDENTIFIER -> "<identifier: $value>"
                QUOTED_STRING -> "<quoted_string: $value>"
                COMMENT -> "<comment: $value>"
                else -> "<unknown>"
            }
        }

        /**
         * Indicates whether this token contains a string.
         */
        val isString: Boolean
            get() = type == IDENTIFIER || type == QUOTED_STRING

        /**
         * Indicates whether this token contains an EOL or EOF.
         */
        val isEOL: Boolean
            get() = type == EOL || type == EOF
    }

    class TokenizerException(filename: String, line: Int, var baseMessage: String) : TextParseException("$filename:$line: $baseMessage") {

    }

    /**
     * Creates a Tokenizer from a string.
     *
     * @param s The String to tokenize.
     */
    constructor(s: String) : this(ByteArrayInputStream(s.toByteArray())) {}

    /**
     * Creates a Tokenizer from an arbitrary input stream.
     *
     * @param is The InputStream to tokenize.
     */
    init {
        var `is` = inputStream
        if (`is` !is BufferedInputStream) {
            `is` = BufferedInputStream(`is`)
        }
        this.`is` = PushbackInputStream(`is`, 2)
        ungottenToken = false
        multiline = 0
        quoting = false
        delimiters = delim
        current = Token()
        sb = StringBuilder()
        filename = "<none>"
        line = 1
    }

    /**
     * Creates a Tokenizer from a file.
     *
     * @param f The File to tokenize.
     */
    constructor(f: File) : this(FileInputStream(f)) {
        wantClose = true
        filename = f.name
    }

    /**
     * Gets the next token from a tokenizer and converts it to a string.
     *
     * @return The next token in the stream, as a string.
     *
     * @throws TextParseException The input was invalid or not a string.
     * @throws IOException An I/O error occurred.
     */
    @Throws(IOException::class, TextParseException::class)
    fun getString(): String {
        val next = get()
        if (!next.isString) {
            throw exception("expected a string")
        }

        return next.value!! // we check if this is a string with .isString
    }
    /**
     * Gets the next token from a tokenizer.
     *
     * @param wantWhitespace If true, leading whitespace will be returned as a
     * token.
     * @param wantComment If true, comments are returned as tokens.
     *
     * @return The next token in the stream.
     *
     * @throws TextParseException The input was invalid.
     * @throws IOException An I/O error occurred.
     */
    @JvmOverloads
    @Throws(IOException::class, TokenizerException::class)
    operator fun get(wantWhitespace: Boolean = false, wantComment: Boolean = false): Token {
        var type: Int
        var c: Int
        if (ungottenToken) {
            ungottenToken = false
            if (current.type == WHITESPACE) {
                if (wantWhitespace) {
                    return current
                }
            } else if (current.type == COMMENT) {
                if (wantComment) {
                    return current
                }
            } else {
                if (current.type == EOL) {
                    line++
                }
                return current
            }
        }
        val skipped = skipWhitespace()
        if (skipped > 0 && wantWhitespace) {
            return current.set(WHITESPACE, null)
        }
        type = IDENTIFIER
        sb.setLength(0)
        while (true) {
            c = char
            if (c == -1 || delimiters.indexOf(c.toChar()) != -1) {
                if (c == -1) {
                    return if (quoting) {
                        throw exception("EOF in " + "quoted string")
                    } else if (sb.length == 0) {
                        current.set(EOF, null)
                    } else {
                        current.set(type, sb)
                    }
                }
                if (sb.length == 0 && type != QUOTED_STRING) {
                    return if (c == '('.code) {
                        multiline++
                        skipWhitespace()
                        continue
                    } else if (c == ')'.code) {
                        if (multiline <= 0) {
                            throw exception("invalid " + "close " + "parenthesis")
                        }
                        multiline--
                        skipWhitespace()
                        continue
                    } else if (c == '"'.code) {
                        if (!quoting) {
                            quoting = true
                            delimiters = quotes
                            type = QUOTED_STRING
                        } else {
                            quoting = false
                            delimiters = delim
                            skipWhitespace()
                        }
                        continue
                    } else if (c == '\n'.code) {
                        current.set(EOL, null)
                    } else if (c == ';'.code) {
                        while (true) {
                            c = char
                            if (c == '\n'.code || c == -1) {
                                break
                            }
                            sb.append(c.toChar())
                        }
                        if (wantComment) {
                            ungetChar(c)
                            current.set(COMMENT, sb)
                        } else if (c == -1 && type != QUOTED_STRING) {
                            checkUnbalancedParens()
                            current.set(EOF, null)
                        } else if (multiline > 0) {
                            skipWhitespace()
                            sb.setLength(0)
                            continue
                        } else {
                            current.set(EOL, null)
                        }
                    } else {
                        throw IllegalStateException()
                    }
                } else {
                    ungetChar(c)
                }
                break
            } else if (c == '\\'.code) {
                c = char
                if (c == -1) {
                    throw exception("unterminated escape sequence")
                }
                sb.append('\\')
            } else if (quoting && c == '\n'.code) {
                throw exception("newline in quoted string")
            }
            sb.append(c.toChar())
        }
        if (sb.length == 0 && type != QUOTED_STRING) {
            checkUnbalancedParens()
            return current.set(EOF, null)
        }
        return current.set(type, sb)
    }

    @Throws(IOException::class)
    private fun skipWhitespace(): Int {
        var skipped = 0
        while (true) {
            val c = char
            if (c != ' '.code && c != '\t'.code) {
                if (!(c == '\n'.code && multiline > 0)) {
                    ungetChar(c)
                    return skipped
                }
            }
            skipped++
        }
    }

    @get:Throws(IOException::class)
    private val char: Int
        get() {
            var c = `is`.read()
            if (c == '\r'.code) {
                val next = `is`.read()
                if (next != '\n'.code) {
                    `is`.unread(next)
                }
                c = '\n'.code
            }
            if (c == '\n'.code) {
                line++
            }
            return c
        }

    @Throws(IOException::class)
    private fun ungetChar(c: Int) {
        if (c == -1) {
            return
        }
        `is`.unread(c)
        if (c == '\n'.code) {
            line--
        }
    }

    @Throws(TextParseException::class)
    private fun checkUnbalancedParens() {
        if (multiline > 0) {
            throw exception("unbalanced parentheses")
        }
    }

    /**
     * Creates an exception which includes the current state in the error message
     *
     * @param s The error message to include.
     *
     * @return The exception to be thrown
     */
    fun exception(s: String): TextParseException {
        return TokenizerException(filename, line, s)
    }

    /**
     * Gets the next token from a tokenizer, ensures it is an unquoted string,
     * and converts it to a string.
     *
     * @return The next token in the stream, as a string.
     *
     * @throws TextParseException The input was invalid or not an unquoted string.
     * @throws IOException An I/O error occurred.
     */
    @Throws(IOException::class, TextParseException::class)
    fun getIdentifier(): String = _getIdentifier("an identifier")

    @Throws(IOException::class, TextParseException::class)
    private fun _getIdentifier(expected: String): String {
        val next = get()
        if (next.type != IDENTIFIER) {
            throw exception("expected $expected")
        }

        return next.value!! // we check with the identifier type
    }

    /**
     * Gets the next token from a tokenizer and converts it to an unsigned 32 bit
     * integer.
     *
     * @return The next token in the stream, as an unsigned 32 bit integer.
     *
     * @throws TextParseException The input was invalid or not an unsigned 32
     * bit integer.
     * @throws IOException An I/O error occurred.
     */
    @Throws(IOException::class, TokenizerException::class)
    fun getUInt32(): Long {
        val l = getLong()
        if (l < 0 || l > 0xFFFFFFFFL) {
            throw exception("expected an 32 bit unsigned integer")
        }
        return l
    }

    /**
     * Gets the next token from a tokenizer and converts it to a long.
     *
     * @return The next token in the stream, as a long.
     *
     * @throws TextParseException The input was invalid or not a long.
     * @throws IOException An I/O error occurred.
     */
    @Throws(IOException::class, TokenizerException::class)
    fun getLong(): Long {
        val next = _getIdentifier("an integer")
        if (!Character.isDigit(next[0])) {
            throw exception("expected an integer")
        }
        return try {
            next.toLong()
        } catch (e: NumberFormatException) {
            throw exception("expected an integer")
        }
    }

    /**
     * Gets the next token from a tokenizer and converts it to an unsigned 16 bit
     * integer.
     *
     * @return The next token in the stream, as an unsigned 16 bit integer.
     *
     * @throws TextParseException The input was invalid or not an unsigned 16
     * bit integer.
     * @throws IOException An I/O error occurred.
     */
    @Throws(IOException::class)
    fun getUInt16(): Int {
        val l = getLong()
        if (l < 0 || l > 0xFFFFL) {
            throw exception("expected an 16 bit unsigned integer")
        }
        return l.toInt()
    }

    /**
     * Gets the next token from a tokenizer and converts it to an unsigned 8 bit
     * integer.
     *
     * @return The next token in the stream, as an unsigned 8 bit integer.
     *
     * @throws TextParseException The input was invalid or not an unsigned 8
     * bit integer.
     * @throws IOException An I/O error occurred.
     */
    @Throws(IOException::class, TextParseException::class)
    fun getUInt8(): Int {
        val l = getLong()
        if (l < 0 || l > 0xFFL) {
            throw exception("expected an 8 bit unsigned integer")
        }
        return l.toInt()
    }

    /**
     * Gets the next token from a tokenizer and parses it as a TTL.
     *
     * @return The next token in the stream, as an unsigned 32 bit integer.
     *
     * @throws TextParseException The input was not valid.
     * @throws IOException An I/O error occurred.
     * @see TTL
     */
    @Throws(IOException::class)
    fun getTTL(): Long {
        val next = _getIdentifier("a TTL value")
        return try {
            TTL.parseTTL(next)
        } catch (e: NumberFormatException) {
            throw exception("expected a TTL value")
        }
    }

    /**
     * Gets the next token from a tokenizer and parses it as if it were a TTL.
     *
     * @return The next token in the stream, as an unsigned 32 bit integer.
     *
     * @throws TextParseException The input was not valid.
     * @throws IOException An I/O error occurred.
     * @see TTL
     */
    @Throws(IOException::class, TokenizerException::class)
    fun getTTLLike(): Long {
        val next = _getIdentifier("a TTL-like value")
        return try {
            TTL.parse(next, false)
        } catch (e: NumberFormatException) {
            throw exception("expected a TTL-like value")
        }
    }

    /**
     * Gets the next token from a tokenizer and converts it to a name.
     *
     * @param origin The origin to append to relative names.
     *
     * @return The next token in the stream, as a name.
     *
     * @throws TextParseException The input was invalid or not a valid name.
     * @throws IOException An I/O error occurred.
     * @throws RelativeNameException The parsed name was relative, even with the
     * origin.
     * @see Name
     */
    @Throws(IOException::class, RelativeNameException::class)
    fun getName(origin: Name?): Name {
        val next = _getIdentifier("a name")

        return try {
            val name = Name.fromString(next, origin)
            if (!name.isAbsolute) {
                throw RelativeNameException(name)
            }
            name
        } catch (e: TextParseException) {
            throw exception(e.message ?: "")
        }
    }

    /**
     * Gets the next token from a tokenizer and converts it to a byte array
     * containing an IP address.
     *
     * @param family The address family.
     *
     * @return The next token in the stream, as an byte array representing an IP
     * address.
     *
     * @throws TextParseException The input was invalid or not a valid address.
     * @throws IOException An I/O error occurred.
     * @see Address
     */
    @Throws(IOException::class)
    fun getAddressBytes(family: Int): ByteArray {
        val next = _getIdentifier("an address")

        if (family == Address.IPv4 && IPv4.isValid(next)) {
            return IPv4.toBytes(next)
        } else if (family == Address.IPv6 && IPv6.isValid(next)) {
            return IPv6.toBytes(next)
        }
        throw exception("Invalid address: $next")
    }

    /**
     * Gets the next token from a tokenizer and converts it to an IP Address.
     *
     * @param family The address family.
     *
     * @return The next token in the stream, as an InetAddress
     *
     * @throws TextParseException The input was invalid or not a valid address.
     * @throws IOException An I/O error occurred.
     * @see Address
     */
    @Throws(IOException::class)
    fun getAddress(family: Int): InetAddress {
        val next = _getIdentifier("an address")

        if (IPv4.isValid(next)) {
            return IPv4.toAddress(next)!!
        }
        if (IPv6.isValid(next)) {
            return IPv6.toAddress(next)!!
        }
        throw UnknownHostException("Unable to create an address from: $next")
    }

    /**
     * Gets the next token from a tokenizer, which must be an EOL or EOF.
     *
     * @throws TextParseException The input was invalid or not an EOL or EOF token.
     * @throws IOException An I/O error occurred.
     */
    @Throws(IOException::class)
    fun getEOL(): Unit {
        val next = get()
        if (next.type != EOL && next.type != EOF) {
            throw exception("expected EOL or EOF")
        }
    }

    /**
     * Gets the remaining string tokens until an EOL/EOF is seen, concatenates
     * them together, and converts the base64 encoded data to a byte array.
     *
     * @return The byte array containing the decoded strings, or null if there
     * were no strings to decode.
     *
     * @throws TextParseException The input was invalid.
     * @throws IOException An I/O error occurred.
     */
    @get:Throws(IOException::class)
    val base64: ByteArray?
        get() = getBase64(false)

    /**
     * Gets the remaining string tokens until an EOL/EOF is seen, concatenates
     * them together, and converts the base64 encoded data to a byte array.
     *
     * @param required If true, an exception will be thrown if no strings remain;
     * otherwise null be be returned.
     *
     * @return The byte array containing the decoded strings, or null if there
     * were no strings to decode.
     *
     * @throws TextParseException The input was invalid.
     * @throws IOException An I/O error occurred.
     */
    @Throws(IOException::class)
    fun getBase64(required: Boolean): ByteArray? {
        val s = remainingStrings() ?: return if (required) {
            throw exception("expected base64 encoded string")
        } else {
            null
        }

        // have to validate the base-64 encoded strings first.
        val chars = s.toCharArray()
        for (aChar in chars) {
            if (aChar.code > 256 || INTERNAL[aChar.code] != 1) {
                // not valid
                throw TextParseException("Invalid base64 character!")
            }
        }
        return Base64.getDecoder().decode(s) ?: throw exception("invalid base64 encoding")
    }

    /**
     * Returns a concatenation of the remaining strings from a Tokenizer.
     */
    @Throws(IOException::class)
    private fun remainingStrings(): String? {
        var buffer: StringBuilder? = null
        while (true) {
            val t = get()
            if (!t.isString) {
                break
            }
            if (buffer == null) {
                buffer = StringBuilder()
            }
            buffer.append(t.value)
        }
        unget()
        return buffer?.toString()
    }

    /**
     * Returns a token to the stream, so that it will be returned by the next call
     * to get().
     *
     * @throws IllegalStateException There are already ungotten tokens.
     */
    fun unget() {
        check(!ungottenToken) { "Cannot unget multiple tokens" }
        if (current.type == EOL) {
            line--
        }
        ungottenToken = true
    }

    /**
     * Gets the remaining string tokens until an EOL/EOF is seen, concatenates
     * them together, and converts the hex encoded data to a byte array.
     *
     * @return The byte array containing the decoded strings, or null if there
     * were no strings to decode.
     *
     * @throws TextParseException The input was invalid.
     * @throws IOException An I/O error occurred.
     */
    @get:Throws(IOException::class)
    val hex: ByteArray?
        get() = getHex(false)

    /**
     * Gets the remaining string tokens until an EOL/EOF is seen, concatenates
     * them together, and converts the hex encoded data to a byte array.
     *
     * @param required If true, an exception will be thrown if no strings remain;
     * otherwise null be be returned.
     *
     * @return The byte array containing the decoded strings, or null if there
     * were no strings to decode.
     *
     * @throws TextParseException The input was invalid.
     * @throws IOException An I/O error occurred.
     */
    @Throws(IOException::class)
    fun getHex(required: Boolean): ByteArray? {
        val s = remainingStrings() ?: return if (required) {
            throw exception("expected hex encoded string")
        } else {
            null
        }
        return base16.fromString(s) ?: throw exception("invalid hex encoding")
    }

    /**
     * Gets the next token from a tokenizer and decodes it as hex.
     *
     * @return The byte array containing the decoded string.
     *
     * @throws TextParseException The input was invalid.
     * @throws IOException An I/O error occurred.
     */
    @get:Throws(IOException::class)
    val hexString: ByteArray
        get() {
            val next = _getIdentifier("a hex string")
            return base16.fromString(next) ?: throw exception("invalid hex encoding")
        }

    /**
     * Gets the next token from a tokenizer and decodes it as base32.
     *
     * @param b32 The base32 context to decode with.
     *
     * @return The byte array containing the decoded string.
     *
     * @throws TextParseException The input was invalid.
     * @throws IOException An I/O error occurred.
     */
    @Throws(IOException::class)
    fun getBase32String(b32: base32): ByteArray {
        val next = _getIdentifier("a base32 string")
        return b32.fromString(next) ?: throw exception("invalid base32 encoding")
    }

    /**
     * Closes any files opened by this tokenizer.
     */
    override fun close() {
        if (wantClose) {
            try {
                `is`.close()
            } catch (ignored: IOException) {
            }
        }
    }

    companion object {
        private val VALID = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray()
        private val INTERNAL = IntArray(256)

        init {
            Arrays.fill(INTERNAL, -1)
            var i = 0
            val iS = VALID.size
            while (i < iS) {
                INTERNAL[VALID[i].code] = 1
                i++
            }
            INTERNAL['='.code] = 1
        }

        private const val delim = " \t\n;()\""
        private const val quotes = "\""

        /**
         * End of file
         */
        const val EOF = 0

        /**
         * End of line
         */
        const val EOL = 1

        /**
         * Whitespace; only returned when wantWhitespace is set
         */
        const val WHITESPACE = 2

        /**
         * An identifier (unquoted string)
         */
        const val IDENTIFIER = 3

        /**
         * A quoted string
         */
        const val QUOTED_STRING = 4

        /**
         * A comment; only returned when wantComment is set
         */
        const val COMMENT = 5
    }
}
