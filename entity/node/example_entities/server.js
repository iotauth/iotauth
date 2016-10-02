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
 * Example server entity.
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

// session keys
var sessionKeyCacheForClients = [];
var sessionKeyCacheForSubscribe = [];

// distributionKey = {val: Buffer, absValidity: Date() format}
var distributionKey = null;

function handleSessionKeyResp(sessionKeyList, receivedDistKey, callbackParams) {
    if (receivedDistKey != null) {
        console.log('updating distribution key: ' + util.inspect(receivedDistKey));
        distributionKey = receivedDistKey;
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

var connectedClients = [];
var tempLargeDataBuf;

function sendToClients(message) {
    for (var i = 0; i < connectedClients.length; i++) {
        if (connectedClients[i] == null) {
            continue;
        }
        try{
            connectedClients[i].send(new Buffer(message));
        }
        catch (err) {
            console.log('error while sending to client#' + i + ': ' + err.message);
            console.log('removing this client from the list...');
            connectedClients[i] = null;
        }
    }
};

function initMqttSubscribe(topic) {
    // ping request period 600 seconds
    var mqttClient = mqtt.connect('mqtt://localhost', {keepalive: 600});
    mqttClient.on('connect', function () {
        console.log('connected to the mqtt broker, start subscribing...');
        mqttClient.subscribe(topic);
    });
    mqttClient.on('message', function (topic, message) {
        console.log('received a mqtt message!');

        var obj = common.parseIoTSP(message);
        if (obj.msgType == msgType.SECURE_PUB) {
            console.log('received secure pub!');
            var ret = iotAuth.parseDecryptSecureMqtt(obj.payload,
            	sessionKeyCacheForSubscribe);
            if (ret.data.length > 65535) {
            	console.log('seqNum: ' + ret.seqNum);
                console.log('data is too large to display, to store in file use saveData command');
                tempLargeDataBuf = ret.data;
            }
            else {
            	console.log('seqNum: ' + ret.seqNum + ' data: ' + topic + ' : ' + ret.data.toString());
            }
        }
        else {
            console.log('received INSECURE pub!');
            // message is Buffer 
            console.log(topic + ' : ' + message);
        }
    });
};


function sendSessionKeyRequest(purpose, numKeys, callbackParams) {
    var options = {
        authHost: authInfo.host,
        authPort: authInfo.port,
        entityName: entityInfo.name,
        numKeysPerRequest: numKeys,
        purpose: purpose,
        distProtocol: entityInfo.distProtocol,
        distributionKey: distributionKey,
        //distributionCryptoSpec,
        //publicKeyCryptoSpec,
        authPublicKey: authInfo.publicKey,
        entityPrivateKey: entityInfo.privateKey
    };
    iotAuth.sendSessionKeyReq(options, handleSessionKeyResp, callbackParams);
};

function commandInterpreter() {
    var chunk = process.stdin.read();
    if (chunk != null) {
        var input = chunk.toString().trim();
        var idx = input.indexOf(' ');
        var command;
        var message;
        if (idx < 0) {
            command = input;
        }
        else {
            command = input.slice(0, idx);
            message = input.slice(idx + 1);
        }

        if (command == 'showKeys') {
            console.log('showKeys command. distribution key and session keys: ');
            console.log('distribution key: '+ util.inspect(distributionKey));
            console.log('Session keys for Clients: ');
            console.log(util.inspect(sessionKeyCacheForClients));
            console.log('Session keys for Subscribe: ');
            console.log(util.inspect(sessionKeyCacheForSubscribe));
        }
        else if (command == 'skReqSub') {
            console.log('skReqSub (Session key request for target subscribe topic) command');
            var numKeys = 3;
            if (message != undefined) {
                numKeys = parseInt(message);
            }
            sendSessionKeyRequest({subTopic: 'Ptopic'}, numKeys, {targetSessionKeyCache: 'Subscribe'});
        }
        else if (command == 'skReqPub') {
            console.log('skReqSub (Session key request for target publish topic) command');
            var numKeys = 1;
            if (message != undefined) {
                numKeys = parseInt(message);
            }
            sendSessionKeyRequest({pubTopic: 'Ptopic'}, numKeys, {targetSessionKeyCache: 'Clients'});
        }
        else if (command == 'mqtt') {
            console.log('mqtt command, init mqtt connection');
            initMqttSubscribe('Ptopic');
        }
        else if (command == 'send') {
            console.log('send command');
            if (message == undefined) {
                console.log('no message!');
                return;
            }
            sendToClients(message);
        }
        else if (command == 'sendFile') {
            console.log('sendFile command');
            var fileName = '../data_examples/data.bin';
            if (message != undefined) {
                fileName = message;
            }
            var fileData = fs.readFileSync(fileName);
            console.log('file data length: ' + fileData.length);
            sendToClients(fileData);
        }
        else if (command == 'saveData') {
            console.log('saveData command');
            if (tempLargeDataBuf == undefined) {
                console.log('No data to be saved!');
            }
            var fileName = '../data_examples/tempLargeData.bin';
            if (message != undefined) {
                fileName = message;
            }
            fs.writeFileSync(fileName, tempLargeDataBuf);
            console.log('file data saved to ' + fileName);
        }
        else if (command == 'exp2') {
            console.log('exp2 command, experiment setup for scenario 2 with broker');
            console.log('connecting to mqtt with topic Ptopic');
            initMqttSubscribe('Ptopic');
            console.log('requesting 1 key for subscribe');
            var numKeys = 1;
            sendSessionKeyRequest({subTopic: 'Ptopic'}, numKeys, {targetSessionKeyCache: 'Subscribe'});
        }
        else {
            console.log('unrecognized command: ' + command);
        }
    }
    console.log(entityInfo.name + ':' + entityInfo.group + ' prompt>');
};

var configFilePath = 'configs/net1/server.config';
if (process.argv.length > 2) {
    configFilePath = process.argv[2];
}

var entityConfig = iotAuth.loadEntityConfig(configFilePath);
entityInfo = entityConfig.entityInfo;
authInfo = entityConfig.authInfo;
listeningServerInfo = entityConfig.listeningServerInfo;
cryptoInfo = entityConfig.cryptoInfo;

if (entityInfo.usePermanentDistKey) {
    var absValidity = new Date().getTime() + iotAuth.parseTimePeriod(entityInfo.distKeyValidity);
    distributionKey = {
        val: entityInfo.permanentDistKey,
        absValidity: new Date(absValidity)
    };
}

function onServerListening() {
    console.log(entityInfo.name + ' bound on port ' + listeningServerInfo.port);
};
function onServerError(message) {
    console.error('Error in server - details: ' + message);
};
function onClientRequest(handshake1Payload, serverSocket, sendHandshake2Callback) {
    var keyId = handshake1Payload.readUIntBE(0, common.S_KEY_ID_SIZE);
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

function initializeSecureServer() {
    var options = {
        serverPort: listeningServerInfo.port,
        sessionCryptoSpec: cryptoInfo.sessionCryptoSpec
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
initializeSecureServer();

process.stdin.on('readable', commandInterpreter);

