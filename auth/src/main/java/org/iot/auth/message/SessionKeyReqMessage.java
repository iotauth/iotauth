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
 *      authNonce:    /Buffer/, (AUTH_NONCE_SIZE)
 *      numKeys: /UInt32BE/,
 *      sender: /string/, (senderLen UInt8)
 *      purpose: /JSON/
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
        _entityNonce = decPayload.slice(curIndex, curIndex + ENTITY_NONCE_SIZE);
        curIndex += ENTITY_NONCE_SIZE;

        _authNonce = decPayload.slice(curIndex, curIndex + AUTH_NONCE_SIZE);
        curIndex += AUTH_NONCE_SIZE;

        _numKeys = decPayload.getInt(curIndex);
        curIndex += 4;

        BufferedString bufStr = decPayload.getBufferedString(curIndex);
        _entityName = bufStr.getString();
        curIndex += bufStr.length();

        // TODO: Now assuming rest of payload is JSON string, should be fixed?
        //bufStr = decPayload.getBufferedString(curIndex);
        //System.out.println(bufStr.getString());

        String msg = new String(decPayload.slice(curIndex).getRawBytes());
        _logger.info("Received JSON: {}", msg);
        _purpose = (JSONObject) new JSONParser().parse(msg);
        curIndex += bufStr.length();
    }

    public Buffer getEntityNonce() {
        return _entityNonce;
    }
    public Buffer getAuthNonce() {
        return _authNonce;
    }
    public String getEntityName() {
        return _entityName;
    }
    public int getNumKeys() {
        return _numKeys;
    }
    public JSONObject getPurpose() {
        return _purpose;
    }

    private Buffer _entityNonce;
    private Buffer _authNonce;
    private int _numKeys;
    private String _entityName;
    private JSONObject _purpose;
    private static final Logger _logger = LoggerFactory.getLogger(SessionKeyReqMessage.class);

}
