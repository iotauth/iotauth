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

package org.iot.auth.db;

/**
 * A class for representing purpose field of cached session key table.
 * @author Hokeun Kim
 */
public class SessionKeyPurpose {
    public SessionKeyPurpose(CommunicationTargetType targetType, String target) {
        this(targetType, target, null);
    }

    /**
     * @param targetEntityName For an ACTION targeting a specific entity named at request time
     * (e.g., a locker identified by a scanned QR code), the target entity's name; null for a solo
     * action with no target entity, and ignored for all other target types.
     */
    public SessionKeyPurpose(CommunicationTargetType targetType, String target, String targetEntityName) {
        if (targetType == CommunicationTargetType.TARGET_GROUP ||
                targetType == CommunicationTargetType.TARGET_GROUP_WITH_RESOURCE) {
            this.targetType = "Group";
        }
        else if (targetType == CommunicationTargetType.PUBLISH_TOPIC ||
                targetType == CommunicationTargetType.SUBSCRIBE_TOPIC) {
            this.targetType = "PubSub";
        }
        else if (targetType == CommunicationTargetType.FILE_SHARING_TEAM) {
            this.targetType = "FileSharing";
        }
        else if (targetType == CommunicationTargetType.DELEGATION) {
            this.targetType = "Delegation";
        }
        else if (targetType == CommunicationTargetType.ACTION) {
            this.targetType = "Action";
        }
        else {
            throw new RuntimeException("Unrecognized communication target type for SessionKeyPurpose");
        }
        this.target = target;
        this.targetEntityName = (targetType == CommunicationTargetType.ACTION) ? targetEntityName : null;
    }
    public String toString() {
        if (targetEntityName != null) {
            return targetType + ":" + target + ":" + targetEntityName;
        }
        return targetType + ":" + target;
    }
    private String targetType;
    private String target;
    private String targetEntityName;
}
