/*
 * Copyright (c) 2016, Regents of the University of California
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * IOTAUTH_COPYRIGHT_VERSION_1
 */

package org.iot.auth.io;

import java.util.Arrays;
import java.util.Base64;

/**
 * A class for input/output buffer for Auth's binary communication with entities over TCP/IP
 * @author Hokeun Kim
 */
public class Buffer {
    public static final int BYTE_SIZE = 1;
    public static final int INT_SIZE = 4;
    public static final int LONG_SIZE = 8;

    public static String toHexString(byte[] bytes, int offset, int length) {
        StringBuilder ret = new StringBuilder();
        for (int i = offset; i < offset + length; i++) {
            ret.append(String.format("%02x ", bytes[i]));
        }
        return ret.toString();
    }

    public static String toHexString(byte[] bytes) {
        return Buffer.toHexString(bytes, 0, bytes.length);
    }

    public String toHexString() {
        return this.toHexString(bytes);
    }

    public String toConsecutiveHexString(byte[] bytes, int offset, int length) {
        StringBuilder ret = new StringBuilder();
        for (int i = offset; i < offset + length; i++) {
            ret.append(String.format("%02x", bytes[i]));
        }
        return ret.toString();
    }
    public String toConsecutiveHexString() {
        return toConsecutiveHexString(bytes, 0, bytes.length);
    }

    public Buffer(int size) {
        bytes = new byte[size];
    }

    public Buffer(byte[] bytes) {
        this.bytes = Arrays.copyOf(bytes, bytes.length);
    }
    public Buffer(byte[] bytes, int size) {
        this.bytes = Arrays.copyOf(bytes, size);
    }

    public Buffer(Buffer buf) {
        bytes = Arrays.copyOf(buf.getRawBytes(), buf.getRawBytes().length);
    }

    public byte[] getRawBytes() {
        return bytes;
    }

    public int length() {
        return bytes.length;
    }

    public void putBytes(byte[] value, int index, int length) {
        if (index <= (bytes.length - length)) {
            System.arraycopy(value, 0, bytes, index, length);
        }
        else {
            throw new IndexOutOfBoundsException();
        }
    }

    public void putBytes(byte[] value, int index) {
        putBytes(value, index, value.length);
    }

    // Parameter order is always value, index, length.
    public void putByte(byte value, int index) {
        if (index < bytes.length) {
            bytes[index] = value;
        }
        else {
            throw new IndexOutOfBoundsException();
        }
    }

    // bytes in big endian
    public void putNumber(long value, int index, int length) {
        if (index <= (bytes.length - length)) {
            for (int i = index + length - 1; i >= index; i--) {
                bytes[i] = (byte)(value & 0xff);
                value >>= 8;
            }
        }
        else {
            throw new IndexOutOfBoundsException();
        }
    }

    // 4 bytes
    public void putInt(int value, int index) {
        putNumber((long) value, index, INT_SIZE);
    }

    // 8 bytes
    public void putLong(long value, int index) {
        putNumber(value, index, LONG_SIZE);
    }

    public byte getByte(int index) {
        if (index < bytes.length) {
            return bytes[index];
        }
        else {
            throw new IndexOutOfBoundsException();
        }
    }

    // bytes in big endian
    public long getNumber(int index, int length) {
        if (index <= (bytes.length - length)) {
            long value = 0;
            for (int i = index; i < index + length; i++) {
                value <<= 8;
                value += (0xff & bytes[i]);
            }
            return value;
        }
        else {
            throw new IndexOutOfBoundsException();
        }
    }

    public int getInt(int index) {
        return (int)getNumber(index, INT_SIZE);
    }

    public long getLong(int index) {
        return getNumber(index, LONG_SIZE);
    }

    // read VariableLengthInt
    public VariableLengthInt getVariableLengthInt(int index) {
        return new VariableLengthInt(bytes, index);
    }

    public BufferedString getBufferedString(int index) {
        VariableLengthInt strLen = new VariableLengthInt(bytes, index);
        index += strLen.getRawBytes().length;
        byte[] str = Arrays.copyOfRange(bytes, index, index + strLen.getNum());
        return new BufferedString(strLen, str);
    }

    public void concat(Buffer buf) {
        byte[] newData = Arrays.copyOf(bytes, bytes.length + buf.length());
        System.arraycopy(buf.getRawBytes(), 0, newData, bytes.length, buf.length());
        bytes = newData;
    }

    public Buffer slice(int from, int to) {
        byte[] newData = Arrays.copyOfRange(bytes, from, to);
        return new Buffer(newData);
    }

    public Buffer slice(int from) {
        return slice(from, length());

    }

    public boolean equals(Buffer another) {
        return Arrays.equals(bytes, another.getRawBytes());
    }

    public String toBase64() {
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static Buffer fromBase64(String base64) {
        return new Buffer(Base64.getDecoder().decode(base64));
    }

    private byte[] bytes;
}
