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

/**
 * Abstract Class that defines the utilization of the basic message setters and getters.
 * <pre>
 * IoTSP (IoT Secure Protocol) Message format
 * {
 *      msgType: /UInt8/,
 *      payloadLen: /variable-length integer encoding/
 *      payload: /Buffer/
 * } </pre>
 * Created by lsmon on 6/14/16.
 * Inspired by khkz
 */
public abstract class MessageAbstract {
    /**
     * The MessageType defined on {@link MessageType}
     * @return MessageType.getValue()
     */
    public abstract byte getMessageType();

    /**
     * Sets the MessageType for the implementation of this abstraction.
     *
     * @param type Message type to be set.
     */
    public abstract void setMessageType(MessageType type);

    /**
     * Gets the defined that the pay load length must to be set.
     * @return payLoadLength
     */
    public abstract int getPayLoadLength();

    /**
     * Sets the pay load length.
     * @param payLoadLength Pay load length to be set
     */
    public abstract void setPayLoadLength(int payLoadLength);

    /**
     * Gets the {@link Buffer} of this message
     * @return Buffer
     */
    public abstract Buffer getBuffer();

    /**
     * Sets the buffer of this message
     * @param buffer Buffer to be set.
     */
    public abstract void setBuffer(Buffer buffer);
}
