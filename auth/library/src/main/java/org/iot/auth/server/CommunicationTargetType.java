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

package org.iot.auth.server;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Hokeun Kim
 */
public enum CommunicationTargetType {
    UNKNOWN(0),
    TARGET_GROUP(1),
    PUBLISH_TOPIC(20),
    SUBSCRIBE_TOPIC(21),
    SESSION_KEY_ID(30);

    public int getValue() {
        return value;
    }

    CommunicationTargetType(int value) {
        this.value = value;
    }

    public static CommunicationTargetType fromStringValue(String value) {
        if (value.equals("Group")) {
            return TARGET_GROUP;
        }
        else if (value.equals("PubTopic")) {
            return PUBLISH_TOPIC;
        }
        else if (value.equals("SubTopic")) {
            return SUBSCRIBE_TOPIC;
        }
        else {
            return UNKNOWN;
        }
    }

    private static final Map<Integer, CommunicationTargetType> typesByValue =
            new HashMap<Integer, CommunicationTargetType>();

    static {
        for (CommunicationTargetType type : CommunicationTargetType.values()) {
            typesByValue.put(type.value, type);
        }
    }

    private final int value;
}
