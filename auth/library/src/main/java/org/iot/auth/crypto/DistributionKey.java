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

package org.iot.auth.crypto;

import org.iot.auth.io.Buffer;

import java.util.Date;

/**
 * A class for distribution key between an entity and Auth.
 * <pre>
 * DistributionKey Format
 * {
 *      ExpirationTime: /UIntBE, DIST_KEY_EXPIRATION_TIME_SIZE Bytes, Date() format/, // for absolute validity period
 *      val: /Buffer/
 * } </pre>
 * @author Hokeun Kim
 */
public class DistributionKey extends SymmetricKey {
    public static final int DIST_KEY_EXPIRATION_TIME_SIZE = 6;

    public DistributionKey(SymmetricKeyCryptoSpec cryptoSpec, long expirationTime, Buffer serializedKeyVal) {
        super(cryptoSpec, expirationTime, serializedKeyVal);
    }
    public DistributionKey(SymmetricKeyCryptoSpec cryptoSpec, long expirationTime) {
        super(cryptoSpec, new Date().getTime() + expirationTime);
    }

    public DistributionKey makeMacOnly() {
        return new DistributionKey(getCryptoSpec().makeMacOnly(), getRawExpirationTime(),
                getSerializedKeyVal(null, getMacKeyVal()));
    }
    public String toString() {
        return "Expiration Time: " + getExpirationTime() + "\tCipherKey: " + getCipherKeyVal().toHexString() +
                "\tMacKey: " + getMacKeyVal().toHexString();
    }
    public Buffer serialize() {
        Buffer buf = new Buffer(DIST_KEY_EXPIRATION_TIME_SIZE);
        int curIndex = 0;
        buf.putNumber(getRawExpirationTime(), curIndex, DIST_KEY_EXPIRATION_TIME_SIZE);
        curIndex += DIST_KEY_EXPIRATION_TIME_SIZE;

        buf.concat(getSerializedKeyVal());
        return buf;
    }
    public static DistributionKey fromBuffer(SymmetricKeyCryptoSpec cryptoSpec, Buffer buffer) {
        int curIndex = 0;
        long expirationTime = buffer.getNumber(curIndex, DIST_KEY_EXPIRATION_TIME_SIZE);
        curIndex += DIST_KEY_EXPIRATION_TIME_SIZE;
        return new DistributionKey(cryptoSpec, expirationTime, buffer.slice(curIndex));
    }
}
