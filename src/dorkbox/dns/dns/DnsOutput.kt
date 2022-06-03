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

import io.netty.buffer.ByteBuf
import io.netty.buffer.Unpooled

/**
 * A class for rendering DNS messages.
 *
 * @author Brian Wellington
 */
class DnsOutput(
    /**
     * @param byteBuf The ByteBuf to use
     */
    val byteBuf: ByteBuf) {

    private var marked = false

    /**
     * Create a new DnsOutput with a specified size.
     *
     * @param size The initial size
     */
    @JvmOverloads
    constructor(size: Int = 32) : this(Unpooled.buffer(size))

    /**
     * Returns the current position.
     */
    fun current(): Int {
        return byteBuf.writerIndex()
    }

    /**
     * Resets the current position of the output stream to the specified index.
     *
     * @param index The new current position.
     *
     * @throws IllegalArgumentException The index is not within the output.
     */
    fun jump(index: Int) {
        require(index < byteBuf.writerIndex()) {
            // we haven't written data to this point yet, and the contract for jump() is that it can only jump to a PREVIOUSLY written spot
            "Unable to jump to invalid position " + index + ". Max is " + byteBuf.writerIndex()
        }
        byteBuf.writerIndex(index)
    }

    /**
     * Saves the current state of the output stream.
     *
     * @throws IllegalArgumentException The index is not within the output.
     */
    fun save() {
        marked = true
        byteBuf.markWriterIndex()
    }

    /**
     * Restores the input stream to its state before the call to [.save].
     */
    fun restore() {
        check(marked) { "Not marked first" }
        byteBuf.resetWriterIndex()
        marked = false
    }

    /**
     * Writes an unsigned 8 bit value to the stream.
     *
     * @param val The value to be written
     */
    fun writeU8(`val`: Int) {
        check(`val`.toLong(), 8)
        byteBuf.ensureWritable(1)
        byteBuf.writeByte(`val`)
    }

    private fun check(`val`: Long, bits: Int) {
        var max: Long = 1
        max = max shl bits
        require(!(`val` < 0 || `val` > max)) { "$`val` out of range for $bits bit value" }
    }

    /**
     * Writes an unsigned 16 bit value to the stream.
     *
     * @param val The value to be written
     */
    fun writeU16(`val`: Int) {
        check(`val`.toLong(), 16)
        byteBuf.ensureWritable(2)
        byteBuf.writeShort(`val`)
    }

    /**
     * Writes an unsigned 16 bit value to the specified position in the stream.
     *
     * @param val The value to be written
     * @param where The position to write the value.
     */
    fun writeU16At(`val`: Int, where: Int) {
        check(`val`.toLong(), 16)

        // save and set both the read/write index, otherwise if the read index is > write index, errors happen.
        val saved = byteBuf.writerIndex()
        val readSaved = byteBuf.readerIndex()
        byteBuf.setIndex(where, where)
        byteBuf.ensureWritable(2)
        byteBuf.writeShort(`val`)

        // put the read/write back to where it was (since this was an operation to write a value at a specific position)
        byteBuf.writerIndex(saved)
        byteBuf.readerIndex(readSaved)
    }

    /**
     * Writes an unsigned 32 bit value to the stream.
     *
     * @param val The value to be written
     */
    fun writeU32(`val`: Long) {
        check(`val`, 32)
        byteBuf.ensureWritable(4)
        byteBuf.writeInt(`val`.toInt())
    }
    /**
     * Writes a byte array to the stream.
     *
     * @param b The array to write.
     * @param off The offset of the array to start copying data from.
     * @param len The number of bytes to write.
     */
    @JvmOverloads
    fun writeByteArray(b: ByteArray, off: Int = 0, len: Int = b.size) {
        byteBuf.ensureWritable(len)
        byteBuf.writeBytes(b, off, len)
    }

    /**
     * Writes a counted string from the stream.  A counted string is a one byte
     * value indicating string length, followed by bytes of data.
     *
     * @param s The string to write.
     */
    fun writeCountedString(s: ByteArray) {
        require(s.size <= 0xFF) { "Invalid counted string" }
        byteBuf.ensureWritable(1 + s.size)
        byteBuf.writeByte(s.size)
        byteBuf.writeBytes(s, 0, s.size)
    }

    /**
     * Returns a byte array containing the current contents of the stream.
     */
    fun toByteArray(): ByteArray {
        val out = ByteArray(byteBuf.writerIndex())
        byteBuf.readBytes(out, 0, out.size)
        return out
    }
}
