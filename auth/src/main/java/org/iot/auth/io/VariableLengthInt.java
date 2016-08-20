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

/**
 * A class for representing a variable length integer.
 * @author Hokeun Kim
 */

public class VariableLengthInt {
    public VariableLengthInt(int num) {
        this.num = num;
        int temp = num;
        int size = 1;
        while (temp > 127) {
            temp >>= 7;
            size++;
        }
        bytes = new byte[size];
        int idx = 0;
        while (num > 127) {
            bytes[idx] = (byte)(128 | num & 127);
            num >>= 7;
            idx++;
        }
        bytes[idx] = (byte)num;
    }
    public VariableLengthInt(byte[] buf, int offset) {
        num = 0;
        for (int i = 0; i < buf.length && i < 5; i++) {
            num |= (buf[offset + i] & 127) << (7 * i);
            if ((buf[offset + i] & 128) == 0) {
                bytes = new byte[i + 1];
                System.arraycopy(buf, offset, bytes, 0, i + 1);
                return;
            }
        }
        throw new IllegalArgumentException();
    }

    public Buffer serialize() {
        return new Buffer(bytes);
    }

    public byte[] getRawBytes() {
        return bytes;
    }
    public int getNum() {
        return num;
    }
    private int num;
    private byte[] bytes;
}