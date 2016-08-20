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

/** This accessor is authenticated/authorized by a local authorization entity, for the
 *  Internet of Things (IoT), called 'Auth'. 
 *
 *  This accessor requires the 'socket', 'buffer' and 'crypto' module.
 *
 *  @accessor net/IoTAuthService
 *
 *  @input {string} host The IP address or domain name of server. Defaults to 'localhost'.
 *  @input {int} port The port on the server to connect to. Defaults to -1, which means
 *   wait for a non-negative input before connecting.
 *  @input toSend The data to be sent over the secure connection.
 *  @output {boolean} connected Output `true` on connected and `false` on disconnected.
 *  @output received The data received over the secure connection.
 *
 *  @parameter {string} authHost The IP address or domain name of an Auth. Defaults to 'localhost'.
 *  @parameter {int} authPort The port on the Auth to connect to.
 *  @parameter {string} authCertPath The name of the file that stores Auth's certificate that
 *    this client will use for communication with the Auth.
 *   
 *  @parameter {string} entityName The entity's unique name.
 *  @parameter {string} entityPrivateKeyPath The name of the file that stores entity's private key,
 *    that will be used for communication with the Auth.
 *   
 *  @parameter {string} publicCipherAlgorithm FIXME: should be given by authCert
 *  @parameter {string} signAlgorithm FIXME: should be given by authCert
 *
 *  @parameter {string} distCipherAlgorithm The symmetric cipher algorithm to be used for distribution of
 *    session keys.
 *  @parameter {string} distHashAlgorithm The secure hash algorithm to be used for distribution of
 *    session keys.
 *
 *  @author Hokeun Kim
 */

"use strict";

var socket = require('socket');
var buffer = require('buffer');
var crypto = require('crypto');

exports.setup = function() {
	this.input('purpose');
	this.output('sessionKey', {
		type : 'string'
	});
	
	this.parameter('authHost', {
        type : 'string',
        value : 'localhost'
    });
    this.parameter('authPort', {
        value: -1,
        type: 'int'
    });
    this.parameter('authCertPath', {
        value: '',
        type: 'string'
    });
    
    this.parameter('entityName', {
        value: '',
        type: 'string'
    });
    this.parameter('entityPrivateKeyPath', {
        value: '',
        type: 'string'
    });
    
    this.parameter('publicCipherAlgorithm', {
        value: '',
        type: 'string'
    });
    this.parameter('signAlgorithm', {
        value: '',
        type: 'string'
    });
    this.parameter('distCipherAlgorithm', {
        value: '',
        type: 'string'
    });
    this.parameter('distHashAlgorithm', {
        value: '',
        type: 'string'
    });
};

//////////////// beginning of common code
var msgType = {
    AUTH_HELLO: 0,
    AUTH_SESSION_KEY_REQ: 10,
    AUTH_SESSION_KEY_RESP: 11,
    SESSION_KEY_REQ_IN_PUB_ENC: 20,
    SESSION_KEY_RESP_WITH_DIST_KEY: 21,    // Includes distribution message (session keys)
    SESSION_KEY_REQ: 22,         // Distribution message
    SESSION_KEY_RESP: 23         // Distribution message
};

var AUTH_NONCE_SIZE = 8;
var S_KEY_ID_SIZE = 8;
var ABS_VALIDITY_SIZE = 6;
var REL_VALIDITY_SIZE = 6;
var DIST_CIPHER_KEY_SIZE = 16;               // 256 bit key = 32 bytes
var SESSION_CIPHER_KEY_SIZE = 16;            // 128 bit key = 16 bytes

// verialbe length integer encoding
function numToVarLenInt(num) {
    var buf = new buffer.Buffer(0);
    while (num > 127) {
        var extraBuf = new buffer.Buffer(1);
        extraBuf.writeUInt8(128 | num & 127);
        buf = buffer.concat([buf, extraBuf]);
        num >>= 7;
    }
    var extraBuf = new buffer.Buffer(1);
    extraBuf.writeUInt8(num);
    buf = buffer.concat([buf, extraBuf]);
    return buf;
};

function varLenIntToNum(buf, offset) {
    var num = 0;
    for (var i = 0; i < buf.length && i < 5; i++) {
        num |= (buf.get(offset + i) & 127) << (7 * i);
        if ((buf.get(offset + i) & 128) == 0) {
            return {num: num, bufLen: i + 1};
            break;
        }
    }
    return null;
};

var serializeIoTSP = function(obj) {
    if (obj.msgType == undefined || obj.payload == undefined) {
        console.log('Error: IoTSP msgType or payload is missing.');
        return;
    }
    var msgTypeBuf = new buffer.Buffer(1);
    msgTypeBuf.writeUInt8(obj.msgType, 0);
    var payLoadLenBuf = numToVarLenInt(obj.payload.length);
    return buffer.concat([msgTypeBuf, payLoadLenBuf, obj.payload]);
};

var parseIoTSP = function(buf) {
    var msgTypeVal = buf.readUInt8(0);
    var ret = varLenIntToNum(buf, 1);
    var payloadVal = buf.slice(1 + ret.bufLen);
    return {msgType: msgTypeVal, payloadLen: ret.num, payload: payloadVal};
};

var parseAuthHello = function(buf) {
    var authId = buf.readUInt32BE(0);
    var nonce = buf.slice(4, 4 + AUTH_NONCE_SIZE);
    return {authId: authId, nonce: nonce};
};

var serializeSessionKeyReq = function(obj) {
    if (obj.nonce == undefined || obj.replyNonce == undefined || obj.sender == undefined
        || obj.purpose == undefined || obj.numKeys == undefined) {
        console.log('Error: SessionKeyReq nonce or replyNonce '
            + 'or purpose or numKeys is missing.');
        return;
    }
    var buf = new buffer.Buffer(AUTH_NONCE_SIZE * 2 + 5);
    obj.nonce.copy(buf, 0);
    obj.replyNonce.copy(buf, AUTH_NONCE_SIZE);
    buf.writeUInt32BE(obj.numKeys, AUTH_NONCE_SIZE * 2);
    buf.writeUInt8(obj.sender.length, AUTH_NONCE_SIZE * 2 + 4);

    var senderBuf = new buffer.Buffer(obj.sender);
    var purposeBuf = new buffer.Buffer(JSON.stringify(obj.purpose));
    return buffer.concat([buf, senderBuf, purposeBuf]);
};

var serializeSessionKeyReqWithDistributionKey = function(senderName,
    sessionKeyReq, distributionKeyVal, cipherAlgorithm, hashAlgorithm) {
    var sessionKeyReqBuf = serializeSessionKeyReq(sessionKeyReq);
    var encBuf = new buffer.Buffer(crypto.symmetricEncryptWithHash(sessionKeyReqBuf.getArray(),
    	distributionKeyVal, cipherAlgorithm, hashAlgorithm));

    var senderBuf = new buffer.Buffer(senderName);
    var lengthBuf = new buffer.Buffer(1);
    lengthBuf.writeUInt8(senderBuf.length);
    return buffer.concat([lengthBuf, senderBuf, encBuf]);
};

var parseDistributionKey = function(buf) {
    var absValidity = new Date(buf.readUIntBE(0, ABS_VALIDITY_SIZE));
    var keyVal = buf.slice(ABS_VALIDITY_SIZE, ABS_VALIDITY_SIZE + DIST_CIPHER_KEY_SIZE);
    return {val: keyVal, absValidity: absValidity};
};

var parseSessionKey = function(buf) {
    var keyId = buf.readUIntBE(0, S_KEY_ID_SIZE);
    var absValidityValue = buf.readUIntBE(S_KEY_ID_SIZE, ABS_VALIDITY_SIZE);
    var absValidity = new Date(buf.readUIntBE(S_KEY_ID_SIZE, ABS_VALIDITY_SIZE));
    var relValidity = buf.readUIntBE(S_KEY_ID_SIZE + ABS_VALIDITY_SIZE, REL_VALIDITY_SIZE);
    var curIndex =  S_KEY_ID_SIZE + ABS_VALIDITY_SIZE + REL_VALIDITY_SIZE;
    var keyVal = buf.slice(curIndex, curIndex + SESSION_CIPHER_KEY_SIZE);
    return {id: keyId, val: keyVal, absValidity: absValidity, relValidity: relValidity};
};

var SESSION_KEY_BUF_SIZE = S_KEY_ID_SIZE + ABS_VALIDITY_SIZE + REL_VALIDITY_SIZE + SESSION_CIPHER_KEY_SIZE;
var parseSessionKeyResp = function(buf) {
    var replyNonce = buf.slice(0, AUTH_NONCE_SIZE);
    var bufIdx = AUTH_NONCE_SIZE;
    
	var cryptoSpecLen = buf.readUInt8(bufIdx);
	bufIdx += 1;
	var cryptoSpecStr = buf.toString(bufIdx, bufIdx + cryptoSpecLen);
	bufIdx += cryptoSpecLen;
	
    var sessionKeyCount = buf.readUInt32BE(bufIdx);

    bufIdx += 4;
    var sessionKeyList = [];
    for (var i = 0; i < sessionKeyCount; i++) {
        var sessionKey = parseSessionKey(buf.slice(bufIdx));
        sessionKeyList.push(sessionKey);
        bufIdx += SESSION_KEY_BUF_SIZE;
    }
    return {replyNonce: replyNonce, sessionKeyList: sessionKeyList};
};
//////////////// end of common code

// auth and entity info
var authPublicKey;
var entityPrivateKey;
var entityName;

// crypto info
var publicCipherAlgorithm;
var signAlgorithm;
var distCipherAlgorithm;
var distHashAlgorithm;

// local variables
var self;
var client = null;
var distributionKey = null;
var sessionKeyList = [];

function outputSessionKey(sessionKey) {
	sessionKey.val = sessionKey.val.getArray();
    self.send('sessionKey', JSON.stringify(sessionKey));
};

function handleSessionKeyResp(obj, myNonce) {
	if (obj.msgType == msgType.SESSION_KEY_RESP_WITH_DIST_KEY) {
        console.log('received session key response with distribution key attached!');
        var distKeyBuf = obj.payload.slice(0, 512);
        var sessionKeyRespBuf = obj.payload.slice(512);
        var pubEncData = distKeyBuf.slice(0, 256).getArray();
        var signature = distKeyBuf.slice(256).getArray();
        var verified = crypto.verifySignature(pubEncData, signature, authPublicKey, signAlgorithm);
        if (!verified) {
        	console.log('Auth signature NOT verified');
        	return;
        }
    	console.log('Auth signature verified');
    	distKeyBuf = new buffer.Buffer(
    		crypto.privateDecrypt(pubEncData, entityPrivateKey, publicCipherAlgorithm));
    	var receivedDistKey = parseDistributionKey(distKeyBuf);
    	
        var ret = crypto.symmetricDecryptWithHash(sessionKeyRespBuf.getArray(),
        	receivedDistKey.val.getArray(), distCipherAlgorithm, distHashAlgorithm);
        if (!ret.hashOk) {
        	console.log('Received hash for session key resp is NOT ok');
        	return;
        }
    	console.log('Received hash for session key resp is ok');
    	sessionKeyRespBuf = new buffer.Buffer(ret.data);
    	var sessionKeyResp = parseSessionKeyResp(sessionKeyRespBuf);
    	if (!sessionKeyResp.replyNonce.equals(myNonce)) {
        	console.log('Auth nonce NOT verified');
        	return;
    	}
    	console.log('Auth nonce verified');
    	
    	console.log('Updating to a new distribution key key');
    	distributionKey = receivedDistKey;
    	console.log(distributionKey);
    	
    	console.log('received ' + sessionKeyResp.sessionKeyList.length + ' session keys');
    	for (var i = 0; i < sessionKeyResp.sessionKeyList.length; i++) {
    		sessionKeyList.push(sessionKeyResp.sessionKeyList[i]);
    	}
    	console.log('Status: Connection closed after receiving auth response.');
	}
	else if (obj.msgType == msgType.SESSION_KEY_RESP) {
		console.log('received session key response encrypted with distribution key');
		var ret = crypto.symmetricDecryptWithHash(obj.payload.getArray(),
        	distributionKey.val.getArray(), distCipherAlgorithm, distHashAlgorithm);
        if (!ret.hashOk) {
        	console.log('Received hash for session key resp is NOT ok');
        	return;
        }
    	console.log('Received hash for session key resp is ok');
        var decBuf = new buffer.Buffer(ret.data);
        var sessionKeyResp = parseSessionKeyResp(decBuf);
    	if (!sessionKeyResp.replyNonce.equals(myNonce)) {
        	console.log('Auth nonce NOT verified');
        	return;
    	}
    	console.log('Auth nonce verified');
    	
    	for (var i = 0; i < sessionKeyResp.sessionKeyList.length; i++) {
    		sessionKeyList.push(sessionKeyResp.sessionKeyList[i]);
    	}
    	console.log('Status: Connection closed after receiving auth response.');
	}
	if (sessionKeyList.length > 0) {
		outputSessionKey(sessionKeyList.shift());
	}
};

function sendSessionKeyReq(authHost, authPort, numKeys, purpose) {
	if (client) {
		// Either the host or the port has changed. Close the previous socket.
		client.close();
	}
    client = new socket.SocketClient(authPort, authHost,
    {
        //'connectTimeout' : this.getParameter('connectTimeout'),
        'discardMessagesBeforeOpen' : false,
        'emitBatchDataAsAvailable' : true,
        //'idleTimeout' : this.getParameter('idleTimeout'),
        'keepAlive' : false,
        //'maxUnsentMessages' : this.getParameter('maxUnsentMessages'),
        //'noDelay' : this.getParameter('noDelay'),
        //'pfxKeyCertPassword' : this.getParameter('pfxKeyCertPassword'),
        //'pfxKeyCertPath' : this.getParameter('pfxKeyCertPath'),
        'rawBytes' : true,
        //'receiveBufferSize' : this.getParameter('receiveBufferSize'),
        'receiveType' : 'byte',
        //'reconnectAttempts' : this.getParameter('reconnectAttempts'),
        //'reconnectInterval' : this.getParameter('reconnectInterval'),
        //'sendBufferSize' : this.getParameter('sendBufferSize'),
        'sendType' : 'byte',
        //'sslTls' : this.getParameter('sslTls'),
        //'trustAll' : this.getParameter('trustAll'),
        //'trustedCACertPath' : this.getParameter('trustedCACertPath')
    });
    client.on('open', function() {
    	console.log('connected to auth');
    });
    var myNonce;
    client.on('data', function(data) {
    	console.log('data received from auth');
		var buf = new buffer.Buffer(data);
		var obj = parseIoTSP(buf);
		if (obj.msgType == msgType.AUTH_HELLO) {
			var authHello = parseAuthHello(obj.payload);
			myNonce = new buffer.Buffer(crypto.randomBytes(AUTH_NONCE_SIZE));
		
            var sessionKeyReq = {
                nonce: myNonce,
                replyNonce: authHello.nonce,
                numKeys: numKeys,
                sender: entityName,
                purpose: purpose
            };
			var msg;
            if (distributionKey == null || distributionKey.absValidity < new Date()) {
                if (distributionKey != null) {
                    console.log('current distribution key expired, '
                        + 'requesting new distribution key as well...');
                }
                else {
                    console.log('no distribution key available yet, '
                        + 'requesting new distribution key as well...');
                }
	            var sessionKeyReqBuf = serializeSessionKeyReq(sessionKeyReq);
	            var payload = new buffer.Buffer(
	            	crypto.publicEncryptAndSign(sessionKeyReqBuf.getArray(),
	            	authPublicKey, entityPrivateKey,
	            	publicCipherAlgorithm, signAlgorithm));
	            msg = {
	            	msgType: msgType.SESSION_KEY_REQ_IN_PUB_ENC,
	            	payload: payload
	            };
            }
            else {
                console.log('distribution key available! ');
                msg = {
                	msgType: msgType.SESSION_KEY_REQ,
                	payload: serializeSessionKeyReqWithDistributionKey(entityName,
                		sessionKeyReq, distributionKey.val.getArray(), distCipherAlgorithm, distHashAlgorithm)
                };
            }
            var toSend = serializeIoTSP(msg).getArray();
            client.send(toSend);
		}
		else if (obj.msgType == msgType.SESSION_KEY_RESP_WITH_DIST_KEY ||
		    obj.msgType == msgType.SESSION_KEY_RESP) {
	    	handleSessionKeyResp(obj, myNonce);
	    	client.close();
		}
    });
    client.on('close', function() {
    	console.log('disconnected from auth');
    });
    client.on('error', function(message) {
    	console.log('an error occurred');
        self.error(message);
    });
	client.open();
};

exports.purposeInputHandler = function() {
	if (sessionKeyList.length > 0) {
		outputSessionKey(sessionKeyList.shift());
	}
	else {
		// JSON.parse(this.get('purpose'))
		// {group: 'Servers'}
		sendSessionKeyReq(this.getParameter('authHost'), this.getParameter('authPort'),
			2, this.get('purpose'));
	}
};

exports.initialize = function () {
	authPublicKey = crypto.loadPublicKey(this.getParameter('authCertPath'));
	entityPrivateKey = crypto.loadPrivateKey(this.getParameter('entityPrivateKeyPath'));
	
	entityName = this.getParameter('entityName');
	publicCipherAlgorithm = this.getParameter('publicCipherAlgorithm');
	signAlgorithm = this.getParameter('signAlgorithm');
	distCipherAlgorithm = this.getParameter('distCipherAlgorithm');
	distHashAlgorithm = this.getParameter('distHashAlgorithm');
	
	self = this;
	
	this.addInputHandler('purpose',
		this.exports.purposeInputHandler.bind(this));
};

/** Close the web socket connection. */
exports.wrapup = function () {
    if (client) {
        client.close();
        console.log('Status: Connection closed in wrapup.');
    }
};
