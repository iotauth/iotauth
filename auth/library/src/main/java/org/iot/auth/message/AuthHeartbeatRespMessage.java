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
import org.iot.auth.io.Buffer;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Class for a response message to a heartbeat request.
 *
 * @author Hokeun Kim
 */
public class AuthHeartbeatRespMessage extends TrustedAuthRespMessage  {
    public AuthHeartbeatRespMessage(Buffer nonce) {
        heartbeatResponseNonce = new Buffer(nonce);
    }

    public Buffer getHeartbeatResponseNonce() {
        return heartbeatResponseNonce;
    }

    @Override
    public void sendAsHttpResponse(HttpServletResponse response) throws IOException {
        // Declare response encoding and types
        response.setContentType("text/html; charset=utf-8");
        // Declare response status code
        response.setStatus(HttpServletResponse.SC_OK);

        // Write back response
        //response.getOutputStream().
        response.getOutputStream().write(heartbeatResponseNonce.getRawBytes());
    }

    public static AuthHeartbeatRespMessage fromAuthHeartbeatReq(AuthHeartbeatReqMessage request) {
        byte[] bytes = request.getHeartbeatNonce().getRawBytes();
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte)~bytes[i];
        }
        return new AuthHeartbeatRespMessage(new Buffer(bytes));
    }

    public static AuthHeartbeatRespMessage fromHttpResponse(ContentResponse contentResponse) {
        byte[] bytes = contentResponse.getContent();
        return new AuthHeartbeatRespMessage(new Buffer(bytes));
    }

    public boolean verifyResponse(Buffer sentNonce) {
        byte[] bytes = sentNonce.getRawBytes();
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte)~bytes[i];
        }
        return heartbeatResponseNonce.equals(new Buffer(bytes));
    }

    Buffer heartbeatResponseNonce;
}
