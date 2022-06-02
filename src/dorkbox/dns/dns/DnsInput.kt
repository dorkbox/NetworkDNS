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
package dorkbox.dns.dns

import dorkbox.dns.dns.exceptions.WireParseException
import io.netty.buffer.ByteBuf
import io.netty.buffer.Unpooled

/**
 * An class for parsing DNS messages.
 *
 * @author Brian Wellington
 */
class DnsInput {
    private var byteBuf: ByteBuf
    private var savedActiveIndex = -1
    private var marked = false

    /**
     * Creates a new DnsInput
     *
     * @param input The byte array to read from
     */
    constructor(input: ByteArray) {
        byteBuf = Unpooled.wrappedBuffer(input)
    }

    /**
     * Creates a new DnsInput from the given [ByteBuf]
     *
     * @param byteBuf The ByteBuf
     */
    constructor(byteBuf: ByteBuf) {
        this.byteBuf = byteBuf
    }

    /**
     * Returns the current position, for reading only
     */
    fun readIndex(): Int {
        return byteBuf.readerIndex()
    }

    /**
     * NOTE: "Active" restricts operations to a specific part of the buffer, defined by the current position + length. Operations that
     * extend BEYOND this section are denied by virtue that we set the max readable length in the underlying ByteBuf.
     *
     * Marks the following bytes in the stream as active, and saves it's state (so it can be restored later)
     *
     * @param len The number of bytes in the active region.
     *
     * @throws IllegalArgumentException The number of bytes in the active region
     * is longer than the remainder of the input.
     */
    fun setActive(len: Int) {
        savedActiveIndex = byteBuf.writerIndex()
        require(len <= byteBuf.readableBytes()) { "cannot set active " + "region past end of input" }
        byteBuf.writerIndex(byteBuf.readerIndex() + len)
    }

    /**
     * Restores the previously set active region.
     */
    fun restoreActive() {
        if (savedActiveIndex > -1) {
            byteBuf.writerIndex(savedActiveIndex)
            savedActiveIndex = -1
        }
    }

    /**
     * Resets the current position of the input stream to the specified index,
     * and clears the active region.
     *
     * @param index The position to continue parsing at.
     *
     * @throws IllegalArgumentException The index is not within the input.
     */
    fun jump(index: Int) {
        require(index < byteBuf.capacity()) { "cannot jump past " + "end of input" }
        byteBuf.readerIndex(index)
        restoreActive()
    }

    /**
     * Saves the current state of the input stream.  Both the current position and
     * the end of the active region are saved.
     *
     * @throws IllegalArgumentException The index is not within the input.
     */
    fun save() {
        marked = true
        byteBuf.markReaderIndex()
    }

    /**
     * Restores the input stream to its state before the call to [.save].
     */
    fun restore() {
        check(marked) { "Not marked first" }
        byteBuf.resetReaderIndex()
    }

    @Throws(WireParseException::class)
    private fun require(n: Int) {
        if (n > remaining()) {
            throw WireParseException("end of input")
        }
    }

    /**
     * Returns the number of bytes that can be read from this stream before
     * reaching the end.
     */
    fun remaining(): Int {
        return byteBuf.readableBytes()
    }

    /**
     * Reads an unsigned 8 bit value from the stream, as an int.
     *
     * @return An unsigned 8 bit value.
     *
     * @throws WireParseException The end of the stream was reached.
     */
    @Throws(WireParseException::class)
    fun readU8(): Int {
        require(1)
        return byteBuf.readUnsignedByte().toInt()
    }

    /**
     * Reads an unsigned 16 bit value from the stream, as an int.
     *
     * @return An unsigned 16 bit value.
     *
     * @throws WireParseException The end of the stream was reached.
     */
    @Throws(WireParseException::class)
    fun readU16(): Int {
        require(2)
        return byteBuf.readUnsignedShort()
    }

    /**
     * Reads an unsigned 32 bit value from the stream, as a long.
     *
     * @return An unsigned 32 bit value.
     *
     * @throws WireParseException The end of the stream was reached.
     */
    @Throws(WireParseException::class)
    fun readU32(): Long {
        require(4)
        return byteBuf.readUnsignedInt()
    }

    /**
     * Reads a byte array of a specified length from the stream into an existing
     * array.
     *
     * @param b The array to read into.
     * @param off The offset of the array to start copying data into.
     * @param len The number of bytes to copy.
     *
     * @throws WireParseException The end of the stream was reached.
     */
    @Throws(WireParseException::class)
    fun readByteArray(b: ByteArray?, off: Int, len: Int) {
        require(len)
        byteBuf.readBytes(b, off, len)
    }

    /**
     * Reads a byte array of a specified length from the stream.
     *
     * @return The byte array.
     *
     * @throws WireParseException The end of the stream was reached.
     */
    @Throws(WireParseException::class)
    fun readByteArray(len: Int): ByteArray {
        require(len)
        val out = ByteArray(len)
        byteBuf.readBytes(out, 0, len)
        return out
    }

    /**
     * Reads a byte array consisting of the remainder of the stream (or the
     * active region, if one is set.
     *
     * @return The byte array.
     */
    fun readByteArray(): ByteArray {
        val len = remaining()
        val out = ByteArray(len)
        byteBuf.readBytes(out, 0, len)
        return out
    }

    /**
     * Reads a counted string from the stream.  A counted string is a one byte
     * value indicating string length, followed by bytes of data.
     *
     * @return A byte array containing the string.
     *
     * @throws WireParseException The end of the stream was reached.
     */
    @Throws(WireParseException::class)
    fun readCountedString(): ByteArray {
        val len = readU8()
        return readByteArray(len)
    }
}
