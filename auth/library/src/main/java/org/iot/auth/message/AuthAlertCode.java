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

import java.util.HashMap;
import java.util.Map;

/**
 * Enumeration for Auth alert code.
 * @author Hokeun Kim
 */
public enum AuthAlertCode {
    INVALID_DISTRIBUTION_KEY((byte)0),
    INVALID_SESSION_KEY_REQ((byte)1),
    UNKNOWN_INTERNAL_ERROR((byte)2);

    public static AuthAlertCode fromByte(byte value) {
        return codesByValue.get(value);
    }
    public byte getValue() {
        return value;
    }

    AuthAlertCode(byte value) {
        this.value = value;
    }

    private static final Map<Byte, AuthAlertCode> codesByValue = new HashMap<>();

    static {
        for (AuthAlertCode type : AuthAlertCode.values()) {
            codesByValue.put(type.value, type);
        }
    }

    private final byte value;
}
