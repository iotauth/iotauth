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
 * SecureCommServer accessor for accessing Auth services and listening to SecureCommClients.
 * @author Hokeun Kim
 */

"use strict";

var fs = require('fs');
var iotAuth = require('iotAuth')
var common = require('common');
var util = require('util');
var msgType = iotAuth.msgType;

// to be loaded from config file
var entityConfig;
var currentDistributionKey;

// for managing connected clients, can be accessed using socketID
var connectedClients = [];

// parameters for SecureCommServer
var parameters =  {
    migrationEnabled: false,
    authFailureThreshold: 3,
    migrationFailureThreshold: 3
};

// migration related variables
var authFailureCount = 0;
var currentMigrationInfoIndex = 0;
var migrationFailureCount = 0;
var trustedAuthPublicKeyList = [];

// session keys for publish-subscribe experiments based individual secure connection using proposed approach
var sessionKeyCacheForClients = [];
var publishSeqNum = 0;

var outputs = {};
var outputHandlers = {};

// constructor
function SecureCommServer(configFilePath) {
	entityConfig = iotAuth.loadEntityConfig(configFilePath);
    if (entityConfig.authInfo.publicKey != null) {
        trustedAuthPublicKeyList.push(entityConfig.authInfo.publicKey);
    }
}

function handleSessionKeyResp(sessionKeyList, receivedDistKey, callbackParams) {
    if (parameters.migrationEnabled) {
        authFailureCount = 0;
        console.log('handleSessionKeyResp: session key request succeeded! authFailureCount: ' + authFailureCount);
    }
    if (receivedDistKey != null) {
        console.log('updating distribution key: ' + util.inspect(receivedDistKey));
        currentDistributionKey = receivedDistKey;
    }
    console.log('received ' + sessionKeyList.length + ' keys');
    if (callbackParams.targetSessionKeyCache == 'Clients') {
    	sessionKeyCacheForClients = sessionKeyCacheForClients.concat(sessionKeyList);
    }
    // session key request was triggered by a client request
    else if (callbackParams.targetSessionKeyCache == 'none') {
        if (sessionKeyList[0].id == callbackParams.keyId) {
            console.log('Session key id is as expected');
            callbackParams.sendHandshake2Callback(callbackParams.handshake1Payload,
                callbackParams.serverSocket, sessionKeyList[0]);
        }
        else {
            console.error('Session key id is NOT as expected');
        }
    }
}

function onServerError(message) {
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
    var info = 'Error in server - details: ' + message;
    outputs.error = info;
    if (outputHandlers.error) {
        outputHandlers.error(info);
    }
}

function sendSessionKeyRequest(purpose, numKeys, callbackParams) {
    var options = iotAuth.getSessionKeyReqOptions(entityConfig, currentDistributionKey, purpose, numKeys);
    var eventHandlers = {
        onError: onServerError
    };
    iotAuth.sendSessionKeyReq(options, handleSessionKeyResp, eventHandlers, callbackParams);
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
        migrationFailureCount = 0;
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
            onError: onServerError
        };
        iotAuth.migrateToTrustedAuth(options, handleMigrationResp, eventHandlers);
    }
}

// event handlers for listening server
function onServerListening() {
	outputs.listening = entityConfig.listeningServerInfo.port;
	if (outputHandlers.listening) {
		outputHandlers.listening(entityConfig.listeningServerInfo.port);
	}
}

function onClientRequest(handshake1Payload, serverSocket, sendHandshake2Callback) {
    var keyId = common.readVariableUIntBE(handshake1Payload, 0, common.SESSION_KEY_ID_SIZE);
    console.log('session key id: ' + keyId);
    var sessionKeyFound = false;
    for (var i = 0; i < sessionKeyCacheForClients.length; i++) {
        if (sessionKeyCacheForClients[i].id == keyId) {
            console.log('found session key');
            sendHandshake2Callback(handshake1Payload, serverSocket, sessionKeyCacheForClients[i]);
            sessionKeyFound = true;
            break;
        }
    }
    if (!sessionKeyFound) {
        console.log('session key NOT found! sending session key id to AuthService');
        var callbackParams = {
            targetSessionKeyCache: 'none',
            keyId: keyId,
            sendHandshake2Callback: sendHandshake2Callback,
            handshake1Payload: handshake1Payload,
            serverSocket: serverSocket
        }
        sendSessionKeyRequest({keyId: keyId}, 1, callbackParams);
    }
}

// event handlers for individual sockets
function onClose(socketID) {
    connectedClients[socketID] = null;
    var info = 'secure connection with the client closed.\n' + 'socket #' + socketID + ' closed';
	outputs.connection = info;
	if (outputHandlers.connection) {
		outputHandlers.connection(info);
	}
}
function onError(message, socketID) {
	var info = 'Error in secure server socket #' + socketID + ' details: ' + message;
	outputs.error = info;
	if (outputHandlers.error) {
		outputHandlers.error(info);
	}
}
function onConnection(socketInstance, entityServerSocket) {
    // registering clients as potential subscribers
    connectedClients[socketInstance.id] = entityServerSocket;
	var info = 'secure connection with the client established.\n' + util.inspect(socketInstance);
	outputs.connection = info;
	if (outputHandlers.connection) {
		outputHandlers.connection(info);
	}
}
function onData(data, socketID) {
    console.log('data received from server via secure communication');
	outputs.received = data;
	outputs.receivedID = data;
    if (outputHandlers.received) {
    	outputHandlers.received({data: data, id: socketID});
    }
}

/*
	toSend = {
		data: Buffer,
		id: Int
	}
*/
function toSendInputHandler(toSend) {
	console.log('toSend: ' + util.inspect(toSend));
    if (toSend == null) {
        console.log('toSend is null, closing all connected clients.');
	    for (var i = 0; i < connectedClients.length; i++) {
	        if (connectedClients[i] == null) {
	            continue;
	        }
            console.log('Closing client id: ' + i)
            connectedClients[i].close();
            connectedClients[i] = null;
        }
    }
	else if (toSend.id != null) {
        console.log('specified socketID: ' + toSend.id);
		if (connectedClients[toSend.id] == null) {
			console.log('client does not exist!');
			return;
		}
        if (!connectedClients[toSend.id].checkSessionKeyValidity()) {
            console.log('session key expired!');
            return;
        }
        try {
        	connectedClients[toSend.id].send(toSend.data);
        }
        catch (err) {
            console.log('error while sending to client#' + toSend.id + ': ' + err.message);
            console.log('removing this client from the list...');
            connectedClients[toSend.id] = null;
        }
	}
	else {
	    var securePublish = null;
	    for (var i = 0; i < connectedClients.length; i++) {
	        if (connectedClients[i] == null) {
	            continue;
	        }
	        // for shared key publish
	        if (sessionKeyCacheForClients.length > 0
	            && sessionKeyCacheForClients[0].id == connectedClients[i].sessionKey.id) {
	            if (securePublish != null) {
	                connectedClients[i].sendRaw(securePublish);
	            }
	            else {
	                var enc = common.serializeEncryptSessionMessage(
	                    {seqNum: publishSeqNum, data: toSend.data},
                        sessionKeyCacheForClients[0], entityConfig.cryptoInfo.sessionCryptoSpec);
	                publishSeqNum++;
	                securePublish = common.serializeIoTSP({
	                    msgType: msgType.SECURE_COMM_MSG,
	                    payload: enc
	                });
	                connectedClients[i].sendRaw(securePublish);
	            }
	            continue;
	        }
	        // for sending to all with different session keys
	        try{
	            connectedClients[i].send(toSend.data);
	        }
	        catch (err) {
	            console.log('error while sending to client#' + i + ': ' + err.message);
	            console.log('removing this client from the list...');
	            connectedClients[i] = null;
	        }
	    }
	}
}

//////// Main interfaces

SecureCommServer.prototype.initialize = function() {
	if (entityConfig.entityInfo.usePermanentDistKey) {
	    currentDistributionKey = entityConfig.entityInfo.permanentDistKey;
	}
	else {
		currentDistributionKey = null;
	}
    outputs = {
    	connection: null,
    	error: null,
    	listening: null,
    	received: null,
    	receivedID: null
    };
    outputHandlers = {
    	connection: null,
    	error: null,
    	listening: null,
    	received: null		// this also outputs receivedID for simplicity, i.e., received = {data: buffer, id: int}
    };
    publishSeqNum = 0;		// for experiments with shared key and individual secure connections
	console.log('initializing secure comm server...');
    var options = {
        serverPort: entityConfig.listeningServerInfo.port,
        sessionCryptoSpec: entityConfig.cryptoInfo.sessionCryptoSpec,
        sessionProtocol: entityConfig.entityInfo.distProtocol,
        handshakeTimeout: entityConfig.entityInfo.connectionTimeout
    };
    var eventHandlers = {
        onServerError: onServerError,      // for server
        onServerListening: onServerListening,
        onClientRequest: onClientRequest,    // for client's communication initialization request

        onClose: onClose,            // for individual sockets
        onError: onError,
        onData: onData,
        onConnection: onConnection
    };
    iotAuth.initializeSecureServer(options, eventHandlers);
}

SecureCommServer.prototype.provideInput = function(port, input) {
	if (port == 'toSend') {
		toSendInputHandler(input);
	}
}

SecureCommServer.prototype.setParameter = function(key, value) {
    parameters[key] = value;
    console.log('current parameters: ' + util.inspect(parameters));
}

SecureCommServer.prototype.latestOutput = function(key) {
	return outputs[key];
}

SecureCommServer.prototype.setOutputHandler = function(key, handler) {
	return outputHandlers[key] = handler;
}

//////// Supportive interfaces

SecureCommServer.prototype.getEntityInfo = function() {
	return entityConfig.entityInfo;
}

SecureCommServer.prototype.getSessionKeysForFutureClients = function(numKeys) {
    // specify auth ID as a value
    sendSessionKeyRequest({cachedKeys: 101}, numKeys, {targetSessionKeyCache: 'Clients'});
}

SecureCommServer.prototype.getSessionKeysForPublish = function(numKeys) {
    sendSessionKeyRequest({pubTopic: 'Ptopic'}, numKeys, {targetSessionKeyCache: 'Clients'});
}

SecureCommServer.prototype.showKeys = function() {
    var result = '';
    result += 'distribution key: '+ util.inspect(currentDistributionKey) + '\n';
    result += 'Session keys for Clients: \n';
    result += util.inspect(sessionKeyCacheForClients) + '\n';
    return result;
}

SecureCommServer.prototype.showSocket = function() {
    var result = '';
    result += 'showSocket command. current client sockets [client count: ' + connectedClients.length + ']: \n';
    for (var i = 0; i < connectedClients.length; i++) {
        result += 'socket ' + i + ': ' + util.inspect(connectedClients[i]) + '\n';
        result += 'socket sessionKey:' + util.inspect(connectedClients[i].sessionKey) + '\n\n';
    }
    return result;
}

SecureCommServer.prototype.migrateToTrustedAuth = function() {
    sendMigrationRequest();
}

SecureCommServer.prototype.setEntityInfo = function(key, value) {
	entityConfig.entityInfo[key] = value;
	console.log('current entityInfo: ' + util.inspect(entityConfig.entityInfo));
}

module.exports = SecureCommServer;
