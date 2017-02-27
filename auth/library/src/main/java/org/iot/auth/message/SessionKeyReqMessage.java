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
import org.iot.auth.io.BufferedString;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A class for a session key req message from an entity.
 * <pre>
 * SessionKeyReq Format
 * {
 *      entityNonce: /Buffer/, (ENTITY_NONCE_SIZE)
 *      nonce: /Buffer/, (AUTH_NONCE_SIZE)
 *      replyNonce:    /Buffer/, (AUTH_NONCE_SIZE)
 *      numKeys: /UInt32BE/,
 *      sender: /string/, (senderLen UInt8)
 *      purpose: JSON,
 *      dhParam: /Buffer/ (optional, Diffie-Hellman parameter)
 * } </pre>
 * @author Hokeun Kim
 */
public class SessionKeyReqMessage extends IoTSPMessage {
    /**
     * Constructor to construct a session key request message from message payload.
     * @param type Message type of the session key request.
     * @param decPayload Payload of the message in Buffer.
     * @throws ParseException When JSON parser fails
     */
    public SessionKeyReqMessage(MessageType type, Buffer decPayload) throws ParseException {
        super(type);
        int curIndex = 0;
        this.entityNonce = decPayload.slice(curIndex, curIndex + ENTITY_NONCE_SIZE);
        curIndex += ENTITY_NONCE_SIZE;

        this.authNonce = decPayload.slice(curIndex, curIndex + AUTH_NONCE_SIZE);
        curIndex += AUTH_NONCE_SIZE;

        this.numKeys = decPayload.getInt(curIndex);
        curIndex += 4;

        BufferedString bufStr = decPayload.getBufferedString(curIndex);
        this.entityName = bufStr.getString();
        curIndex += bufStr.length();

        bufStr = decPayload.getBufferedString(curIndex);
        String msg = bufStr.getString();
        logger.info("Received JSON: {}", msg);
        this.purpose = (JSONObject) new JSONParser().parse(msg);
        curIndex += bufStr.length();

        if (curIndex < decPayload.length()) {
            this.diffieHellmanParam = decPayload.slice(curIndex);
        }
        else {
            this.diffieHellmanParam = null;
        }
    }

    public Buffer getEntityNonce() {
        return entityNonce;
    }
    public Buffer getAuthNonce() {
        return authNonce;
    }
    public String getEntityName() {
        return entityName;
    }
    public int getNumKeys() {
        return numKeys;
    }
    public JSONObject getPurpose() {
        return purpose;
    }
    public Buffer getDiffieHellmanParam() {
        return diffieHellmanParam;
    }

    private Buffer entityNonce;
    private Buffer authNonce;
    private int numKeys;
    private String entityName;
    private JSONObject purpose;
    private Buffer diffieHellmanParam;

    private static final Logger logger = LoggerFactory.getLogger(SessionKeyReqMessage.class);
}
