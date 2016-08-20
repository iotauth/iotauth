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
 * A class for an Auth alert message to an entity, used when there's a problem with communication with the entity.
 * <pre>
 * AuthAlert Format
 * {
 *      AuthAlertCode: /AUTH_ALERT_CODE_SIZE/
 * } </pre>
 * @author Hokeun Kim
 */
public class AuthAlertMessage extends IoTSPMessage {
    protected static final int AUTH_ALERT_CODE_SIZE = 1;

    public AuthAlertMessage(AuthAlertCode authAlertCode) {
        super(MessageType.AUTH_ALERT);
        this.authAlertCode = authAlertCode;
    }
    public Buffer serialize() {
        // in constructor? or with init method?
        payload = new Buffer(AUTH_ALERT_CODE_SIZE);
        payload.putByte(authAlertCode.getValue(), 0);
        return super.serialize();
    }

    protected final AuthAlertCode authAlertCode;
}
