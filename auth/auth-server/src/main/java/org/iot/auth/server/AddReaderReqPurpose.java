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
 * A class for describing the purpose of add reader requests, solely used by EntityConnectionHandler.
 * @author Yeongbin Jo
 */
public class AddReaderReqPurpose {
    public AddReaderReqPurpose(JSONObject purpose) throws InvalidSessionKeyTargetException {
        // purpose keys
        final String AddReader = "AddReader";
        Object objTarget = null;
        CommunicationTargetType targetType = CommunicationTargetType.UNKNOWN;

        if (purpose.containsKey(AddReader)) {
            objTarget = purpose.get(AddReader);
            if (objTarget.getClass() == String.class) {
                targetType = CommunicationTargetType.ADD_READER;
            }
        }
        if (targetType == CommunicationTargetType.UNKNOWN) {
            throw new InvalidSessionKeyTargetException("Unrecognized purpose: " + purpose);
        }
        this.target = objTarget;
    }

    public Object getTarget() {
        return target;
    }
    private Object target;

    private static final Logger logger = LoggerFactory.getLogger(AddReaderReqPurpose.class);

}
