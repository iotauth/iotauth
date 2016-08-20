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
import org.iot.auth.io.VariableLengthInt;


/**
 * A class for reprenting and serializing IoTSP (IoT Secure Protocol) messages between Auth and entities.
 * <pre>
 * IoTSP (IoT Secure Protocol) Message Format
 * {
 *      msgType: /UInt8/,
 *      payloadLen: /variable-length integer encoding/
 *      payload: /Buffer/
 * } </pre>
 * @author Hokeun Kim
 */
public class IoTSPMessage {
    public static final int MSG_TYPE_SIZE = 1;
    public static final int AUTH_NONCE_SIZE = 8;
    protected static final int ENTITY_NONCE_SIZE = 8;

    public IoTSPMessage(MessageType type) {
        this.type = type;
    }

    public IoTSPMessage(MessageType type, Buffer payload) {
        this.type = type;
        this.payload = payload;
    }
    public Buffer serialize() {
        VariableLengthInt varLenInt = new VariableLengthInt(payload.length());
        byte[] payloadLen = varLenInt.getRawBytes();
        Buffer buf = new Buffer(MSG_TYPE_SIZE + payloadLen.length);
        buf.putByte(type.getValue(), 0);
        buf.putBytes(payloadLen, MSG_TYPE_SIZE);

        buf.concat(payload);
        return buf;
    }
    protected final MessageType type;
    protected Buffer payload;
}
