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

import org.iot.auth.AuthServer;
import org.iot.auth.crypto.SessionKey;
import org.iot.auth.db.CommunicationPolicy;
import org.iot.auth.db.CommunicationTargetType;
import org.iot.auth.db.RegisteredEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.ArrayList;

/**
 * A utility class for checking communication policy.
 * @author Hokeun Kim
 */
public class CommunicationPolicyChecker {

    /**
     * When an entity requests a session key with a session key ID, this method checks if the session key is valid for
     * the communication policy of the requesting entity. This check includes target group, purpose, and maximum number
     * of session key owners.
     * @param requestingEntity The entity who sent a session key request based on a session key ID.
     * @param sessionKey The session key found from the session key ID.
     * @return If the check is successful.
     */
    public static boolean checkSessionKeyCommunicationPolicy(
            AuthServer server,
            String requestingEntityGroup,
            String requestingEntityName,
            SessionKey sessionKey) {
        String[] purposeTokens = sessionKey.getPurpose().split(":");
        if (purposeTokens.length != 2) {
            throw new RuntimeException("Wrong session key purpose format. Format must be \"TargetType:Target\"");
        }
        String targetType = purposeTokens[0];
        String target = purposeTokens[1];
        switch (targetType) {
            case "Group":
                if (!target.equals(requestingEntityGroup)) {
                    logger.error("Requesting entity ({})'s target group does not match session key communication policy.",
                            requestingEntityName);
                    return false;
                }
                if (sessionKey.getOwners().length >= sessionKey.getMaxNumOwners()) {
                    logger.error("The maximum of session key owners has already reached for entity: {}, target: {}.",
                            requestingEntityName, target);
                    return false;
                }
                return true;
            case "PubSub":
                // Requesting entity's group must be allowed to subscribe to the topic.
                CommunicationPolicy communicationPolicy = server.getCommunicationPolicy(requestingEntityGroup,
                        CommunicationTargetType.SUBSCRIBE_TOPIC, target);
                if (communicationPolicy == null) {
                    logger.error("Requesting entity ({}) is not allowed to subscribe topic: {}",
                            requestingEntityName, target);
                    return false;
                }
                logger.info("Requesting entity ({}) is allowed to subscribe topic: {}",
                        requestingEntityName, target);
                if (sessionKey.getOwners().length >= communicationPolicy.getMaxNumSessionKeyOwners()) {
                    logger.error("The maximum of session key owners has already reached for entity: {}, target: {}.",
                            requestingEntityName, target);
                    return false;
                }
                return true;
            case "FileSharing":
                String[] SessionkeyOwner = sessionKey.getOwners();
                RegisteredEntity ownerEntity = server.getRegisteredEntity(SessionkeyOwner[0]);
                ArrayList <String> entity_list = server.getFileSharingInfo(ownerEntity.getGroup());
                logger.info("File Sharing List of {}: {}",ownerEntity.getGroup(), entity_list);
                if (!(entity_list.contains(requestingEntityName) || entity_list.contains(requestingEntityGroup)))
                {
                    logger.error("Requesting entity ({})'s target group does not match session key communication policy.",
                        requestingEntityName); 
                    return false;  
                }
                if (sessionKey.getOwners().length >= sessionKey.getMaxNumOwners()) {
                    logger.error("The maximum of session key owners has already reached for entity: {}, target: {}.",
                            requestingEntityName, target);
                    return false;
                }
                return true;
            default:
                throw new RuntimeException("Invalid session key target type: " + targetType);
        }
    }
    private static final Logger logger = LoggerFactory.getLogger(CommunicationPolicyChecker.class);
}
