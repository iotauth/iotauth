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

/** This accessor sets up a secure, authenticated and authorized connection with a server.
 *  It does this by getting authenticated and authorized by a local authentication and authorization
 *  entity called 'Auth'.
 *  'Secure' means that the communications are encrypted; 'authenticated' means that the identity of both
 *  this client and the server are guaranteed by Auth; and 'authorized' means that the client and server
 *  are registered with Auth as eligible to communicate with one another.
 *  
 *  Once a secure connection is established with the server, this accessor can send and/or
 *  receive messages protected by a session key given by Auth. A session key is a 
 *  symmetric key with a validity period. 'Symmetric' means that this client and the server use the same key.
 *  'Protected' means encrypted and/or authenticated.
 *
 *  This accessor will attempt to establish a secure connection with the server specified by parameters (host, port)
 *  when it first receives an input on its input port(FIXME).
 *  To do this it needs to communicate with Auth which is specified by the paramaters (FIXME)
 *  
 *  FIXME: explain what happens if this connection fails, connectionError port
 *  (use throw exception rather than console output)
 *
 *  In order to be authorized by an Auth, there must be an Auth that is running and reachable by this accessor.
 *  
 *  // 2) The HW/SW network entity on which this accessor is running
 *  // should be registered with the Auth. The network entity can be a single device, a virtual
 *  // machine, a software application, etc. -> with the registration instructions
 *
 *  An open-source implementation of Auth is available on public repository (FIXME: 
 *  insert a link to a repository after setting up the repository).
 *
 *  To register this client on which the swarmlet is running, 
 *  1) The client must have a public/private key pair, and a unique name (string).
 *  2) The client's public key and unique name should be stored in Auth's database.
 *  3) The key distribution conditions of the session keys must be set up with the Auth.
 *  These conditions include the cipher and hash algorithms for key distribution, and the
 *  validity periods of the distribution keys. A distribution key is a symmetric key-wrapping
 *  key for session keys.
 *  4) The path of the Auth's certificate (which includes Auth's public key) must be
 *  available to this accessor.
 *  Detailed information of the entity registration can be found in the tutorial available
 *  on (FIXME: put a link to the tutorial here.)
 *  
 *  When the secure connection is established, a `true` boolean is sent to
 *  the `connected` output. If the secure connection is broken during execution, then a `false`
 *  boolean is sent to the `connected` output. The swarmlet could respond to this by
 *  retrying to connect (send an event to either the `port` or `host` input).
 *  
 *  Whenever an input is received on the `toSend` input, the data on that input is sent 
 *  over the secure connection. If the secure connection is not yet established,
 *  input messages that are received before the establishment of the secure connection
 *  will be discarded.
 *
 *  Whenever a message is received from over secure connection, that message is
 *  produced on the `received` output.
 *
 *  When `wrapup()` is invoked, this accessor closes the secure connection.
 *
 *  This accessor requires the 'socket', 'buffer' and 'crypto' module.
 *
 *  @accessor net/IoTAuthorizedClient
 *
 *  @input {string} host The IP address or domain name of server. Defaults to 'localhost'.
 *  @input {int} port The port on the server to connect to. Defaults to -1, which means
 *   wait for a non-negative input before connecting.
 *  @input toSend The data to be sent over the socket.
 *
 *  @output {boolean} connected Output `true` on connected and `false` on disconnected.
 *  @output received The data received from the web socket server.
 *
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
 *  @parameter {string} publicCipherAlgorithm FIXME: should be included in Auth's certificate
 *  @parameter {string} signAlgorithm FIXME: should be included in Auth's certificate
 *
 *  @parameter {string} distCipherAlgorithm The symmetric cipher algorithm to be used for distribution of
 *    session keys.
 *  @parameter {string} distHashAlgorithm The secure hash algorithm to be used for distribution of
 *    session keys.
 *
 *  @parameter {string} serverHost The IP address or domain name of a server. Defaults to 'localhost'.
 *  @parameter {int} serverPort The port on the server to connect to.
 *  @parameter {string} sessionCipherAlgorithm The symmetric cipher algorithm to be used for the
 *    secure connection with the server.
 *  @parameter {string} sessionHashAlgorithm The secure hash algorithm to be used for the
 *    secure connection with the server.
 *
 *  @author Hokeun Kim
 */


"use strict";

var socket = require('socket');
var buffer = require('buffer');
var crypto = require('crypto');

exports.setup = function() {
	this.input('sessionKey', {
		type : 'string'
	});
	this.input('toSend', {
		type : 'string'
	});
	this.output('connected', {
		type: 'boolean'
	});
	this.output('received', {
		type : 'string'
	});
	
	this.parameter('serverHost', {
        type : 'string',
        value : 'localhost'
    });
    this.parameter('serverPort', {
        value: -1,
        type: 'int'
    });
    
    this.parameter('sessionCipherAlgorithm', {
        value: '',
        type: 'string'
    });
    this.parameter('sessionHashAlgorithm', {
        value: '',
        type: 'string'
    });
};

//////////////// beginning of common code
var msgType = {
    SKEY_HANDSHAKE_1: 30,
    SKEY_HANDSHAKE_2: 31,
    SKEY_HANDSHAKE_3: 32,
    SECURE_COMM_MSG: 33,
    FIN_SECURE_COMM: 34,
    SECURE_PUB: 40
};
var HS_NONCE_SIZE = 8;            // handshake nonce size
var S_KEY_ID_SIZE = 8;
var SEQ_NUM_SIZE = 8;

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

/*
    IoTSP (IoT Secure Protocol) Message
    {
        msgType: /UInt8/,
        payloadLen: /variable-length integer encoding/
        payload: /Buffer/
    }
*/
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

/*
    Handshake Format
    {
        nonce: /Buffer/, // encrypted, may be undefined
        replyNonce: /Buffer/, // encrypted, may be undefined
    }
*/
var serializeHandshake = function(obj) {
    if (obj.nonce == undefined && obj.replyNonce == undefined) {
        console.log('Error: handshake should include at least on nonce.');
        return;
    }
    var buf = new buffer.Buffer(1 + HS_NONCE_SIZE * 2);

    // indicates existance of nonces
    var indicator = 0;
    if (obj.nonce != undefined) {
        indicator += 1;
        obj.nonce.copy(buf, 1);
    }
    if (obj.replyNonce != undefined) {
        indicator += 2;
        obj.replyNonce.copy(buf, 1 + HS_NONCE_SIZE);
    }
    buf.writeUInt8(indicator, 0);

    return buf;
};

// buf should be just the unencrypted part
var parseHandshake = function(buf) {
    var obj = {};
    var indicator = buf.readUInt8(0);
    if ((indicator & 1) != 0) {
        // nonce exists
        obj.nonce = buf.slice(1, 1 + HS_NONCE_SIZE);
    }
    if ((indicator & 2) != 0) {
        // replayNonce exists
        obj.replyNonce = buf.slice(1 + HS_NONCE_SIZE, 1 + HS_NONCE_SIZE * 2);
    }
    return obj;
};

/*
    SecureSessionMessage Format
    {
        SeqNum: /Buffer/, // UIntBE, SEQ_NUM_SIZE Bytes
        data: /Buffer/,
    }
*/
var serializeSessionMessage = function(obj) {
    if (obj.seqNum == undefined || obj.data == undefined) {
        console.log('Error: Secure session message seqNum or data is missing.');
        return;
    }
    var seqNumBuf = new buffer.Buffer(SEQ_NUM_SIZE);
    seqNumBuf.writeUIntBE(obj.seqNum, 0, SEQ_NUM_SIZE);
    return buffer.concat([seqNumBuf, obj.data]);
};
var parseSessionMessage = function(buf) {
    var seqNum = buf.readUIntBE(0, SEQ_NUM_SIZE);
    var data = buf.slice(SEQ_NUM_SIZE);
    return {seqNum: seqNum, data: data};
};
//////////////// end of common code

// crypto info
var sessionCipherAlgorithm;
var sessionHashAlgorithm;

// client communication state
var clientCommState = {
    IDLE: 0,
    HANDSHAKE_1_SENT: 10,
    IN_COMM: 30                    // Session message
};

// local variables
var self;
var client = null;
var sessionKey = null;
var currentState = clientCommState.IDLE;
var writeSeqNum = 0;
var readSeqNum = 0;

function initComm(serverHost, serverPort) {
	if (client) {
		// Either the host or the port has changed. Close the previous socket.
		client.close();
	}
    client = new socket.SocketClient(serverPort, serverHost,
    {
        //'connectTimeout' : this.getParameter('connectTimeout'),
        'discardMessagesBeforeOpen' : false,
        'emitBatchDataAsAvailable' : true,
        //'idleTimeout' : this.getParameter('idleTimeout'),
        //'keepAlive' : false,
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
    
    var myNonce;
    client.on('open', function() {
    	console.log('connected to server');
    	if (sessionKey == null) {
	        console.log('No available key');
	        return;
    	}
    	myNonce = new buffer.Buffer(crypto.randomBytes(HS_NONCE_SIZE));
        console.log('chosen nonce: ' + myNonce.inspect());
        var handshake1 = {nonce: myNonce};
        var buf = serializeHandshake(handshake1);
        var encBuf = new buffer.Buffer(crypto.symmetricEncryptWithHash(buf.getArray(),
    		sessionKey.val, sessionCipherAlgorithm, sessionHashAlgorithm));
    	
        var keyIdBuf = new buffer.Buffer(S_KEY_ID_SIZE);
        keyIdBuf.writeUIntBE(sessionKey.id, 0, S_KEY_ID_SIZE);
        var msg = {
            msgType: msgType.SKEY_HANDSHAKE_1,
            payload: buffer.concat([keyIdBuf, encBuf])
        };
        var toSend = serializeIoTSP(msg).getArray();
        client.send(toSend);
        console.log('switching to HANDSHAKE_1_SENT');
        currentState = clientCommState.HANDSHAKE_1_SENT;
    });
    client.on('data', function(data) {
    	console.log('data received from server');
		var obj = parseIoTSP(new buffer.Buffer(data));
    	if (obj.msgType == msgType.SKEY_HANDSHAKE_2) {
            console.log('received session key handshake2!');
            if (currentState != clientCommState.HANDSHAKE_1_SENT) {
                console.log('Error: wrong sequence of handshake, disconnecting...');
                currentState = clientCommState.IDLE;
                client.close();
                return;
            }
            var ret = crypto.symmetricDecryptWithHash(obj.payload.getArray(),
    			sessionKey.val, sessionCipherAlgorithm, sessionHashAlgorithm);
    		if (!ret.hashOk) {
        		console.log('Received hash for handshake2 is NOT ok');
    			return;
    		}
    		console.log('Received hash for handshake2 is ok');
    		var buf = new buffer.Buffer(ret.data);
    		var handshake2 = parseHandshake(buf);
    		if (!handshake2.replyNonce.equals(myNonce)) {
        		console.log('Server nonce NOT verified');
    			return;
    		}
    		console.log('Server nonce verified');
    		var theirNonce = handshake2.nonce;
    		var handshake3 = {replyNonce: theirNonce};
    		buf = serializeHandshake(handshake3);
    		var encBuf = new buffer.Buffer(crypto.symmetricEncryptWithHash(buf.getArray(),
    			sessionKey.val, sessionCipherAlgorithm, sessionHashAlgorithm));
    		var msg = {
    			msgType: msgType.SKEY_HANDSHAKE_3,
    			payload: encBuf
    		};
    		client.send(serializeIoTSP(msg).getArray());
	        console.log('switching to IN_COMM');
	        currentState = clientCommState.IN_COMM;
	        writeSeqNum = 0;
	        readSeqNum = 0;
	        self.send('connected', true);
    	}
    	else if (obj.msgType == msgType.SECURE_COMM_MSG) {
            console.log('received secure communication message!');
            if (currentState != clientCommState.IN_COMM) {
                console.log('Error: it is not in IN_COMM state, disconecting...');
                currentState = clientCommState.IDLE;
                client.close();
                return;
            }
            var ret = crypto.symmetricDecryptWithHash(obj.payload.getArray(),
    			sessionKey.val, sessionCipherAlgorithm, sessionHashAlgorithm);
    		if (!ret.hashOk) {
        		console.log('Received hash for secure comm msg is NOT ok');
    			return;
    		}
    		console.log('Received hash for secure comm msg is ok');
    		var buf = new buffer.Buffer(ret.data);
    		ret = parseSessionMessage(buf);
    		
            if (ret.seqNum != readSeqNum) {
            	console.log('seqNum does not match! expected: ' + readSeqNum + ' received: ' + ret.seqNum);
            }
            readSeqNum++;
        	console.log('seqNum: ' + ret.seqNum + ' data: ' + ret.data);
        	
	        self.send('received', ret.data.toString());
    	}
    });
    client.on('close', function() {
    	console.log('disconnected from server');
        console.log('switching to IDLE');
        currentState = clientCommState.IDLE;
    });
    client.on('error', function(message) {
    	console.log('an error occurred');
        self.error(message);
    });
	client.open();
}

exports.sessionKeyInputHandler = function() {
	sessionKey = JSON.parse(this.get('sessionKey'));
	sessionKey.absValidity = new Date(sessionKey.absValidity);
	console.log(sessionKey);
	initComm(this.getParameter('serverHost'), this.getParameter('serverPort'));
};

exports.toSendInputHandler = function () {
	var toSend = this.get('toSend');
	// May be receiving inputs before client has been set.
	if (client && currentState == clientCommState.IN_COMM) {
		var buf = serializeSessionMessage({seqNum: writeSeqNum, data: new buffer.Buffer(toSend)});
		var encBuf = new buffer.Buffer(crypto.symmetricEncryptWithHash(buf.getArray(),
			sessionKey.val, sessionCipherAlgorithm, sessionHashAlgorithm));
		writeSeqNum++;
		var msg = {
			msgType: msgType.SECURE_COMM_MSG,
			payload: encBuf
		};
		var toSend = serializeIoTSP(msg).getArray();
		client.send(toSend);
	}
	else {
        console.log('Discarding data because socket is not open.');
	}
};

exports.initialize = function () {
	currentState = clientCommState.IDLE;
    writeSeqNum = 0;
    readSeqNum = 0;
	sessionKey = null;
	
	sessionCipherAlgorithm = this.getParameter('sessionCipherAlgorithm');
	sessionHashAlgorithm = this.getParameter('sessionHashAlgorithm');
	
	self = this;
	
	this.addInputHandler('sessionKey',
		this.exports.sessionKeyInputHandler.bind(this));
	this.addInputHandler('toSend',
		this.exports.toSendInputHandler.bind(this));
};

/** Close the web socket connection. */
exports.wrapup = function () {
    if (client) {
        client.close();
        console.log('Status: Connection closed in wrapup.');
        console.log('switching to IDLE state.');
        currentState = clientCommState.IDLE;
    }
};
