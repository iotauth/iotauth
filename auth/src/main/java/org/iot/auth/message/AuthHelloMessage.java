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

package org.iot.auth.message;
import org.iot.auth.io.Buffer;

/**
 * <pre>
 * AuthHello Format
 * {
 *      authId: /UInt32BE/,    // identifier of auth (when auths are replicated)
 *      nonce: /Buffer/
 * } </pre>
 * @author Hokeun Kim
 */
public class AuthHelloMessage extends IoTSPMessage {
    // TODO: is this a right place to put constants?
    protected static final int AUTH_ID_SIZE = 4;

    public AuthHelloMessage(int authId, Buffer authNonce) {
        super(MessageType.AUTH_HELLO);
        this.authId = authId;
        if (authNonce.length() != AUTH_NONCE_SIZE) {
            throw new IllegalArgumentException("Incorrect auth nonce size");
        }
        this.authNonce = authNonce;
    }

    public Buffer serialize() {
        // in constructor? or with init method?
        payload = new Buffer(AUTH_ID_SIZE + AUTH_NONCE_SIZE);
        payload.putInt(authId, 0);
        payload.putBytes(authNonce.getRawBytes(), AUTH_ID_SIZE);
        return super.serialize();
    }
    private int authId;
    private Buffer authNonce;
}
