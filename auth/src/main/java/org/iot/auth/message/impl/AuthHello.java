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

package org.iot.auth.message.impl;

import org.iot.auth.io.Buffer;
import org.iot.auth.message.MessageAbstract;
import org.iot.auth.message.MessageType;

/**
 * Created by lsmon on 6/15/16.
 */
public class AuthHello extends MessageAbstract {
    private byte    _messageType;
    private int     _payLoadLength;
    private Buffer  _buffer;

    private byte[]    _authId;
    private Buffer  _nonce;

    @Override
    public byte getMessageType() {
        return this._messageType;
    }

    @Override
    public void setMessageType(MessageType type) {
        this._messageType = type.getValue();
    }

    @Override
    public int getPayLoadLength() {
        return this._payLoadLength;
    }

    @Override
    public void setPayLoadLength(int payLoadLength) {
        this._payLoadLength = payLoadLength;
    }

    @Override
    public Buffer getBuffer() {
        return this._buffer;
    }

    @Override
    public void setBuffer(Buffer buffer) {
        this._buffer = buffer;
    }

    public byte[] getAuthId() {
        return _authId;
    }

    public void setAuthId(byte[] _authId) {
        this._authId = _authId;
    }

    public Buffer getNonce() {
        return _nonce;
    }

    public void setNonce(Buffer _nonce) {
        this._nonce = _nonce;
    }
}
