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

import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.client.util.BytesContentProvider;
import org.iot.auth.crypto.AuthCrypto;
import org.iot.auth.io.Buffer;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

/**
 * Class for Auth heartbeat request messages
 * @author Hokeun Kim
 */
public class AuthHeartbeatReqMessage extends TrustedAuthReqMessasge  {
    public static final int HEARTBEAT_NONCE_SIZE = 8;
    Buffer heartbeatNonce;
    public AuthHeartbeatReqMessage() {
        heartbeatNonce = AuthCrypto.getRandomBytes(HEARTBEAT_NONCE_SIZE);
    }
    public AuthHeartbeatReqMessage(Buffer heartbeatNonce) {
        this.heartbeatNonce = new Buffer(heartbeatNonce.getRawBytes());
    }

    public Buffer getHeartbeatNonce() {
        return heartbeatNonce;
    }

    // Because of the class name conflict of Request (client's or server's)
    public ContentResponse sendAsHttpRequest(org.eclipse.jetty.client.api.Request postRequest)
            throws TimeoutException, ExecutionException, InterruptedException
    {
        postRequest.param(TrustedAuthReqMessasge.TYPE, type.HEARTBEAT_REQ.name());
        BytesContentProvider contentProvider = new BytesContentProvider(heartbeatNonce.getRawBytes());
        postRequest.content(contentProvider);
        return postRequest.send();
    }

    public static AuthHeartbeatReqMessage fromHttpRequest(org.eclipse.jetty.server.Request baseRequest) throws IOException,
            InvalidKeySpecException, NoSuchAlgorithmException
    {
        InputStream inputStream = baseRequest.getInputStream();
        byte[] bytes = new byte[baseRequest.getContentLength()];
        if (inputStream.read(bytes) != baseRequest.getContentLength()) {
            throw new RuntimeException("Error occurred in reading content of HTTP request");
        }
        Buffer buffer = new Buffer(bytes);
        if (buffer.length() != HEARTBEAT_NONCE_SIZE) {
            throw new RuntimeException("Heartbeat nonce size is not as expected!");

        }
        return new AuthHeartbeatReqMessage(buffer);
    }
}
