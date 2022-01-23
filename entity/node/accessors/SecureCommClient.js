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
var util = require('util');
var msgType = iotAuth.msgType;

var clientCommState = {
    IDLE: 0,
    IN_COMM: 30                    // Session message
};
var currentState;

var entityConfig;
var currentDistributionKey;

var currentSessionKeyList = [];
var currentSessionKey;

var currentSecureClient;

// parameters for SecureCommClient
var parameters =  {
	numKeysPerRequest: 3,
    migrationEnabled: false,
    authFailureThreshold: 3,
    migrationFailureThreshold: 3
};

// migration related variables
var authFailureCount = 0;
var currentMigrationInfoIndex = 0;
var migrationFailureCount = 0;
var trustedAuthPublicKeyList = [];

var outputs = {};
var outputHandlers = {};

// constructor
function SecureCommClient(configFilePath) {
	entityConfig = iotAuth.loadEntityConfig(configFilePath);
    if (entityConfig.authInfo.publicKey != null) {
        trustedAuthPublicKeyList.push(entityConfig.authInfo.publicKey);
    }
}

function onClose() {
    outputs.connected = false;
    if (outputHandlers.connected) {
    	outputHandlers.connected(false);
    }
}

// event handlers
function onError(message) {
    if (parameters.migrationEnabled) {
        if (message.includes('Error occurred in migration request')) {
            migrationFailureCount++;
            console.log('failure in migration to another Auth : migrationFailureCount: ' + migrationFailureCount);
        }
        else if (message.includes('Error occurred in session key request')) {
            authFailureCount++;
            console.log('failure in connection with Auth : authFailureCount: ' + authFailureCount);
            if (authFailureCount >= parameters.authFailureThreshold) {
                console.log('failure count reached threshold (' + parameters.authFailureThreshold + '), try migration...');
                sendMigrationRequest();
            }
        }
    }
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
    console.log('currentSessionKey: ' + util.inspect(currentSessionKey));
    if (currentSecureClient) {
        currentSecureClient.close();
        console.log('Status: Secure connection closed before starting a new connection.');
        currentState = clientCommState.IDLE;
    }
    var options = {
        serverHost: serverHost,
        serverPort: serverPort,
        sessionKey: currentSessionKey,
        sessionCryptoSpec: entityConfig.cryptoInfo.sessionCryptoSpec,
        sessionProtocol: entityConfig.entityInfo.distProtocol,
        handshakeTimeout: entityConfig.entityInfo.connectionTimeout
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
    if (parameters.migrationEnabled) {
        authFailureCount = 0;
        console.log('handleSessionKeyResp: session key request succeeded! authFailureCount: ' + authFailureCount);
    }
    if (receivedDistKey != null) {
        console.log('updating distribution key: ' + util.inspect(receivedDistKey));
        currentDistributionKey = receivedDistKey;
    }
    console.log('received ' + sessionKeyList.length + ' keys');
    currentSessionKeyList = currentSessionKeyList.concat(sessionKeyList);

    if (currentSessionKeyList.length > 0 && callbackParameters != null) {
        initSecureCommWithSessionKey(currentSessionKeyList.shift(),
            callbackParameters.host, callbackParameters.port);
    }

    if (callbackParameters != null && callbackParameters.callback) {
        callbackParameters.callback();
    }
}

function sendSessionKeyRequest(purpose, numKeys, sessionKeyRespCallback, callbackParameters) {
    var options = iotAuth.getSessionKeyReqOptions(entityConfig, currentDistributionKey, purpose, numKeys);
    var eventHandlers = {
        onError: onError
    };
    iotAuth.sendSessionKeyReq(options, sessionKeyRespCallback, eventHandlers, callbackParameters);
}

function handleMigrationResp(newAuthId, newCredential) {
    authFailureCount = 0;
    migrationFailureCount = 0;
    entityConfig.authInfo.id = newAuthId;
    if (entityConfig.entityInfo.usePermanentDistKey) {
        currentDistributionKey =  newCredential;
    }
    else {
        entityConfig.authInfo.publicKey = newCredential;
        trustedAuthPublicKeyList.push(newCredential);
        currentDistributionKey = null;  // previous distribution key should be invalidated
    }
    var currentMigrationInfo = entityConfig.migrationInfo[currentMigrationInfoIndex];
    entityConfig.authInfo.host = currentMigrationInfo.host;
    entityConfig.authInfo.port = currentMigrationInfo.port;
    console.log('migration completed!');
    console.log('new Auth info: !');
    console.log(util.inspect(entityConfig.authInfo));
    rotateMigrationInfoIndex('received migration response, for next round of migration, ');
}

function rotateMigrationInfoIndex(message) {
        console.log(message + 'rotate migration info index from: ' + currentMigrationInfoIndex);
        currentMigrationInfoIndex = ((currentMigrationInfoIndex + 1) % entityConfig.migrationInfo.length);
        console.log('to: ' + currentMigrationInfoIndex);
}

function sendMigrationRequest() {
    if (entityConfig.migrationInfo == null || entityConfig.migrationInfo.length == 0) {
        console.log('Failed to migrate! no information for migration.');
        return;
    }
    if (migrationFailureCount >= parameters.migrationFailureThreshold) {
        rotateMigrationInfoIndex('reached migration failure threshold, ');
        migrationFailureCount = 0;
    }
    var currentMigrationInfo = entityConfig.migrationInfo[currentMigrationInfoIndex];
    if ((entityConfig.authInfo.host == currentMigrationInfo.host)
        && (entityConfig.authInfo.port == currentMigrationInfo.port))
    {
        console.log('Failed to migrate! host/port of current Auth is the same as host of the Auth which we migrate to');
    }
    else {
        var options = iotAuth.getMigrationReqOptions(entityConfig, currentMigrationInfo, trustedAuthPublicKeyList);
        var eventHandlers = {
            onError: onError
        };
        iotAuth.migrateToTrustedAuth(options, handleMigrationResp, eventHandlers);
    }
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
	if (entityConfig.entityInfo.usePermanentDistKey) {
    	currentDistributionKey = entityConfig.entityInfo.permanentDistKey;
	}
	else {
		currentDistributionKey = null;
	}
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
	return entityConfig.targetServerInfoList;
}

SecureCommClient.prototype.getEntityInfo = function() {
	return entityConfig.entityInfo;
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

SecureCommClient.prototype.getSessionKeysForCaching = function(numKeys) {
    sendSessionKeyRequest({group: 'Servers'}, numKeys,
        handleSessionKeyResp, null);
}

SecureCommClient.prototype.migrateToTrustedAuth = function() {
    sendMigrationRequest();
}

SecureCommClient.prototype.setEntityInfo = function(key, value) {
	entityConfig.entityInfo[key] = value;
	console.log('current entityInfo: ' + util.inspect(entityConfig.entityInfo));
}

module.exports = SecureCommClient;
