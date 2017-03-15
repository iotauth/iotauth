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
var mqtt = require('mqtt');
var util = require('util');
var msgType = iotAuth.msgType;


// to be loaded from config file
var entityInfo;
var authInfo;
var listeningServerInfo;
var cryptoInfo;
var currentDistributionKey;

// for managing connected clients, can be accessed using socketID
var connectedClients = [];

// session keys for publish-subscribe experiments based individual secure connection using proposed approach
var sessionKeyCacheForClients = [];

var outputs = {};
var outputHandlers = {};

// constructor
function SecureCommServer(configFilePath) {
	var entityConfig = iotAuth.loadEntityConfig(configFilePath);
	entityInfo = entityConfig.entityInfo;
	authInfo = entityConfig.authInfo;
	listeningServerInfo = entityConfig.listeningServerInfo;
	cryptoInfo = entityConfig.cryptoInfo;
}

function handleSessionKeyResp(sessionKeyList, receivedDistKey, callbackParams) {
    if (receivedDistKey != null) {
        console.log('updating distribution key: ' + util.inspect(receivedDistKey));
        currentDistributionKey = receivedDistKey;
    }
    console.log('received ' + sessionKeyList.length + ' keys');
    if (callbackParams.targetSessionKeyCache == 'Clients') {
    	sessionKeyCacheForClients = sessionKeyCacheForClients.concat(sessionKeyList);
    }
    else if (callbackParams.targetSessionKeyCache == 'Subscribe') {
    	sessionKeyCacheForSubscribe = sessionKeyCacheForSubscribe.concat(sessionKeyList);
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
};

function sendSessionKeyRequest(purpose, numKeys, callbackParams) {
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
    iotAuth.sendSessionKeyReq(options, handleSessionKeyResp, callbackParams);
};

// event handlers for listening server
function onServerListening() {
    console.log(entityInfo.name + ' bound on port ' + listeningServerInfo.port);
};
function onServerError(message) {
    console.error('Error in server - details: ' + message);
};
function onClientRequest(handshake1Payload, serverSocket, sendHandshake2Callback) {
    var keyId = handshake1Payload.readUIntBE(0, common.SESSION_KEY_ID_SIZE);
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
};

// event handlers for individual sockets
function onClose(socketID) {
    console.log('secure connection with the client closed.');
    connectedClients[socketID] = null;
    console.log('socket #' + socketID + ' closed');
};
function onError(message, socketID) {
    console.error('Error in secure server socket #' + socketID +
        ' details: ' + message);
};
function onConnection(socketInstance, entityServerSocket) {
    console.log('secure connection with the client established.');

    console.log(socketInstance);
    // registering clients as potential subscribers
    connectedClients[socketInstance.id] = entityServerSocket;
};
function onData(data, socketID) {
    console.log('data received from server via secure communication');

    if (data.length > 65535) {
        console.log('socketID: ' + socketID);
        console.log('data is too large to display, to store in file use saveData command');
        tempLargeDataBuf = data;
    }
    else {
        console.log('socketID: ' + socketID + ' data: ' + data.toString());
    }
};

//////// Main interfaces

SecureCommServer.prototype.initialize = function() {
	if (entityInfo.usePermanentDistKey) {
	    currentDistributionKey = entityInfo.permanentDistKey;
	}
	else {
		currentDistributionKey = null;
	}
    outputs = {
    	listening: null,
    	connection: null,
    	received: null,
    	receivedID: null
    };
    outputHandlers = {
    	listening: null,
    	connection: null,
    	received: null,
    	//receivedID: null
    };
	console.log('initializing secure comm server...');
    var options = {
        serverPort: listeningServerInfo.port,
        sessionCryptoSpec: cryptoInfo.sessionCryptoSpec,
        sessionProtocol: entityInfo.distProtocol
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
};

//////// Supportive interfaces

SecureCommServer.prototype.getEntityInfo = function() {
	return entityInfo;
};

module.exports = SecureCommServer;