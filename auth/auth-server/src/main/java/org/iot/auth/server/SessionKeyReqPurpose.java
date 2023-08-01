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

import org.iot.auth.db.CommunicationTargetType;
import org.iot.auth.exception.InvalidSessionKeyTargetException;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A class for describing the purpose of session key requests, solely used by EntityConnectionHandler.
 * @author Hokeun Kim
 */
public class SessionKeyReqPurpose {
    public SessionKeyReqPurpose(JSONObject purpose) throws InvalidSessionKeyTargetException {
        // purpose keys
        final String group = "group";
        final String pubTopic = "pubTopic";
        final String subTopic = "subTopic";
        final String keyId = "keyId";
        final String cachedKeys = "cachedKeys";
        final String fileSharing = "FileSharing";

        // TODO: match JSON string (group, pubTopic, subTopic) and CommunicationPolicyTable.db (Group, PubTopic, SubTopic)
        Object objTarget = null;
        this.targetType = CommunicationTargetType.UNKNOWN;

        if (purpose.containsKey(group)) {
            objTarget = purpose.get(group);
            if (objTarget.getClass() == String.class) {
                this.targetType = CommunicationTargetType.TARGET_GROUP;
            }
        } else if (purpose.containsKey(pubTopic)) {
            objTarget = purpose.get(pubTopic);
            if (objTarget.getClass() == String.class) {
                this.targetType = CommunicationTargetType.PUBLISH_TOPIC;
            }
        } else if (purpose.containsKey(subTopic)) {
            objTarget = purpose.get(subTopic);
            if (objTarget.getClass() == String.class) {
                this.targetType = CommunicationTargetType.SUBSCRIBE_TOPIC;
            }
        } else if (purpose.containsKey(keyId)) {
            objTarget = purpose.get(keyId);
            logger.info("{}", objTarget.getClass());
            if (objTarget.getClass() == Integer.class || objTarget.getClass() == Long.class) {
                this.targetType = CommunicationTargetType.SESSION_KEY_ID;
            }
        } else if (purpose.containsKey(cachedKeys)) {
            objTarget = purpose.get(cachedKeys);
            logger.info("{}", objTarget.getClass());
            if (objTarget.getClass() == Integer.class || objTarget.getClass() == Long.class) {
                this.targetType = CommunicationTargetType.CACHED_SESSION_KEYS;
            }
        } else if (purpose.containsKey(fileSharing)) {
            objTarget = purpose.get(fileSharing);
            if (objTarget.getClass() == String.class) {
                this.targetType = CommunicationTargetType.FILE_SHARING;
            }
        }

        if (this.targetType == CommunicationTargetType.UNKNOWN) {
            throw new InvalidSessionKeyTargetException("Unrecognized purpose: " + purpose);
        }
        this.target = objTarget;
    }

    public CommunicationTargetType getTargetType() {
        return targetType;
    }

    public Object getTarget() {
        return target;
    }

    private CommunicationTargetType targetType;
    private Object target;

    private static final Logger logger = LoggerFactory.getLogger(SessionKeyReqPurpose.class);

}
