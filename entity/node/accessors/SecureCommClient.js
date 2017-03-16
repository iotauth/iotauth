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

/**
 * SecureCommClient accessor for accessing Auth services and other servers.
 * @author Hokeun Kim
 */
"use strict";

var iotAuth = require('iotAuth');
var mqtt = require('mqtt');
var util = require('util');
var msgType = iotAuth.msgType;

var clientCommState = {
    IDLE: 0,
    IN_COMM: 30                    // Session message
};
var currentState;

var currentSessionKeyList = [];
var entityInfo;
var authInfo;
var targetServerInfoList;
var cryptoInfo;
var currentDistributionKey;

var currentSessionKey;
var currentSecureClient;

var parameters = {};
var outputs = {};
var outputHandlers = {};

// constructor
function SecureCommClient(configFilePath) {
	var entityConfig = iotAuth.loadEntityConfig(configFilePath);
	entityInfo = entityConfig.entityInfo;
	authInfo = entityConfig.authInfo;
	targetServerInfoList = entityConfig.targetServerInfoList;
	cryptoInfo = entityConfig.cryptoInfo;
}

function onClose() {
    outputs.connected = false;
    if (outputHandlers.connected) {
    	outputHandlers.connected(false);
    }
}

// event handlers
function onError(message) {
	outputs.error = message;
	if (outputHandlers.error) {
		outputHandlers.error(message);
	}
}

function onData(data) {
	outputs.received = data;
    if (outputHandlers.received) {
    	outputHandlers.received(data);
    }
}

function onConnection(entityClientSocket) {
    currentSecureClient = entityClientSocket;
    currentState = clientCommState.IN_COMM;
    outputs.connected = true;
    if (outputHandlers.connected) {
    	outputHandlers.connected(true);
    }
}

function initSecureCommWithSessionKey(sessionKey, serverHost, serverPort) {
    currentSessionKey = sessionKey;
    console.log('currentSessionKey: ' + currentSessionKey);
    if (currentSecureClient) {
        currentSecureClient.close();
        console.log('Status: Secure connection closed before starting a new connection.');
        currentState = clientCommState.IDLE;
    }
    var options = {
        serverHost: serverHost,
        serverPort: serverPort,
        sessionKey: currentSessionKey,
        sessionCryptoSpec: cryptoInfo.sessionCryptoSpec,
        sessionProtocol: entityInfo.distProtocol
    };
    var eventHandlers = {
        onClose: onClose,
        onError: onError,
        onData: onData,
        onConnection: onConnection
    };
    iotAuth.initializeSecureCommunication(options, eventHandlers);
}

function handleSessionKeyResp(sessionKeyList, receivedDistKey, callbackParameters) {
    if (receivedDistKey != null) {
        console.log('updating distribution key: ' + util.inspect(receivedDistKey));
        currentDistributionKey = receivedDistKey;
    }
    console.log('received ' + sessionKeyList.length + ' keys');
    currentSessionKeyList = currentSessionKeyList.concat(sessionKeyList);

    if (currentSessionKeyList.length > 0) {
        initSecureCommWithSessionKey(currentSessionKeyList.shift(),
            callbackParameters.host, callbackParameters.port);
    }

    if (callbackParameters.callback) {
        callbackParameters.callback();
    }
}

function sendSessionKeyRequest(purpose, numKeys, sessionKeyRespCallback, callbackParameters) {
    var options = {
        authHost: authInfo.host,
        authPort: authInfo.port,
        entityName: entityInfo.name,
        numKeysPerRequest: numKeys,
        purpose: purpose,
        distProtocol: entityInfo.distProtocol,
        distributionKey: currentDistributionKey,
        distributionCryptoSpec: cryptoInfo.distributionCryptoSpec,
        publicKeyCryptoSpec: cryptoInfo.publicKeyCryptoSpec,
        authPublicKey: authInfo.publicKey,
        entityPrivateKey: entityInfo.privateKey
    };
    iotAuth.sendSessionKeyReq(options, sessionKeyRespCallback, callbackParameters);
}

/*
serverHostPort = {
	host: 'localhost',
	port: 21200
}
*/
function serverHostPortInputHandler(serverHostPort) {
	if (serverHostPort == null) {
		console.log('ServerHostPort is null, trying to close previous socket...');
		if (currentSecureClient) {
			currentSecureClient.close();
			currentSecureClient = null;
		}
	}
	else {
	    if (currentSessionKeyList.length > 0) {
	        initSecureCommWithSessionKey(currentSessionKeyList.shift(),
	            serverHostPort.host, serverHostPort.port);
	    }
	    else {
	    	// hack to support exp2
	    	if (parameters.keyId) {
	    		sendSessionKeyRequest({keyId: parameters.keyId}, 1,
	    			handleSessionKeyResp, serverHostPort);
	    	}
	    	else {
	    		sendSessionKeyRequest({group: 'Servers'}, parameters.numKeysPerRequest,
	    			handleSessionKeyResp, serverHostPort);
	    	}
	    }
	}
}

function toSendInputHandler(toSend) {
    if (currentSecureClient && currentState == clientCommState.IN_COMM) {
        if (!currentSecureClient.checkSessionKeyValidity()) {
            console.log('session key expired!');
        } else if (!currentSecureClient.send(toSend)) {
            console.log('Error in sending data');
        }
    }
    else {
        console.log('Discarding data because socket is not open.');
    }
}

//////// Main interfaces

SecureCommClient.prototype.initialize = function() {
	console.log('initializing...');
	currentState = clientCommState.IDLE;
	if (entityInfo.usePermanentDistKey) {
    	currentDistributionKey = entityInfo.permanentDistKey;
	}
	else {
		currentDistributionKey = null;
	}
	parameters =  {
		numKeysPerRequest: 3
    };
    outputs = {
    	connected: false,
    	error: null,
    	received: null
    };
    outputHandlers = {
    	connected: null,
    	error: null,
    	received: null
    };
	console.log('current parameters: ' + util.inspect(parameters));
}

SecureCommClient.prototype.provideInput = function(port, input) {
	if (port == 'serverHostPort') {
		serverHostPortInputHandler(input);
	}
	else if (port == 'toSend') {
		toSendInputHandler(input);
	}
}

SecureCommClient.prototype.setParameter = function(key, value) {
	parameters[key] = value;
	console.log('current parameters: ' + util.inspect(parameters));
}

SecureCommClient.prototype.latestOutput = function(key) {
	return outputs[key];
}

SecureCommClient.prototype.setOutputHandler = function(key, handler) {
	return outputHandlers[key] = handler;
}

//////// Supportive interfaces

SecureCommClient.prototype.getTargetServerInfoList = function() {
	return targetServerInfoList;
}

SecureCommClient.prototype.getEntityInfo = function() {
	return entityInfo;
}

SecureCommClient.prototype.showKeys = function() {
    var result = '';
    result += 'distribution key: '+ util.inspect(currentDistributionKey) + '\n';
    result += 'Session keys for Servers: \n';
    result += util.inspect(currentSessionKeyList) + '\n';
    return result;
}

SecureCommClient.prototype.showSocket = function() {
    var result = '';
    result += util.inspect(currentSecureClient) + '\n';
    if (currentSecureClient) {
    	result += 'socket sessionKey:' + util.inspect(currentSecureClient.sessionKey) + '\n';
	}
    return result;
}

module.exports = SecureCommClient;
