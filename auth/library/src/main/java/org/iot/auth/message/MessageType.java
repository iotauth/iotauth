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
 * Enumeration for message types used in communication between an entity and Auth.
 * @author Hokeun Kim, Salomon Lee
 */
public enum MessageType {
    AUTH_HELLO((byte)0),
    ENTITY_HELLO((byte)1),
    AUTH_SESSION_KEY_REQ((byte)10),
    AUTH_SESSION_KEY_RESP((byte)11),
    SESSION_KEY_REQ_IN_PUB_ENC((byte)20),
    /** Includes distribution message (session keys) */
    SESSION_KEY_RESP_WITH_DIST_KEY((byte)21),
    /** Distribution message */
    SESSION_KEY_REQ((byte)22),
    /** Distribution message */
    SESSION_KEY_RESP((byte)23),
    SKEY_HANDSHAKE_1((byte)30),
    SKEY_HANDSHAKE_2((byte)31),
    SKEY_HANDSHAKE_3((byte)32),
    SECURE_COMM_MSG((byte)33),
    FIN_SECURE_COMM((byte)34),
    SECURE_PUB((byte)40),
    /** For migrating registered entities **/
    MIGRATION_REQ_WITH_SIGN((byte)50),
    MIGRATION_RESP_WITH_SIGN((byte)51),
    MIGRATION_REQ_WITH_MAC((byte)52),
    MIGRATION_RESP_WITH_MAC((byte)53),
    /** File sharing reader info **/
    ADD_READER_REQ_IN_PUB_ENC((byte)60),
    ADD_READER_RESP_WITH_DIST_KEY((byte)61),
    ADD_READER_REQ((byte)62),
    ADD_READER_RESP((byte)63),
    AUTH_ALERT((byte)100);

    public static MessageType fromByte(byte value) {
        return typesByValue.get(value);
    }
    public byte getValue() {
        return value;
    }

    MessageType(byte value) {
        this.value = value;
    }

    private static final Map<Byte, MessageType> typesByValue =
            new HashMap<Byte, MessageType>();

    static {
        for (MessageType type : MessageType.values()) {
            typesByValue.put(type.value, type);
        }
    }

    private final byte value;
}
