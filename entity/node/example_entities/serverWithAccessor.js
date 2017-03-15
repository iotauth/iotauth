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
var SecureCommServer = require('../accessors/SecureCommServer');

// to be loaded from config file
var entityInfo;
var authInfo;
var listeningServerInfo;
var cryptoInfo;

var configFilePath = 'configs/net1/server.config';
if (process.argv.length > 2) {
    configFilePath = process.argv[2];
}

var secureCommServer = new SecureCommServer(configFilePath);
secureCommServer.initialize();

/*
// session keys
var sessionKeyCacheForClients = [];
var sessionKeyCacheForSubscribe = [];


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

var publishSeqNum = 0;
function sendToClients(message) {
    var securePublish = null;
    for (var i = 0; i < connectedClients.length; i++) {
        if (connectedClients[i] == null) {
            continue;
        }
        if (sessionKeyCacheForClients.length > 0
            && sessionKeyCacheForClients[0].id == connectedClients[i].sessionKey.id) {
            if (securePublish != null) {
                connectedClients[i].sendRaw(securePublish);
            }
            else {
                var enc = common.symmetricEncryptAuthenticate(
                    {seqNum: publishSeqNum, data: message}, sessionKeyCacheForClients[0], cryptoInfo.sessionCryptoSpec);
                publishSeqNum++;
                securePublish = common.serializeIoTSP({
                    msgType: msgType.SECURE_COMM_MSG,
                    payload: enc
                });
                connectedClients[i].sendRaw(securePublish);
            }
            continue;
        }
        try{
            connectedClients[i].send(message);
        }
        catch (err) {
            console.log('error while sending to client#' + i + ': ' + err.message);
            console.log('removing this client from the list...');
            connectedClients[i] = null;
        }
    }
};

*/

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
        else if (command == 'showSocket') {
            console.log('showSocket command. current client sockets [client count: ' + connectedClients.length + ']: ');
            for (var i = 0; i < connectedClients.length; i++) {
                console.log('socket ' + i + ': ' + util.inspect(connectedClients[i]));
                console.log('socket sessionKey:' + util.inspect(connectedClients[i].sessionKey) + '\n');
            }
        }
        else if (command == 'skReq') {
            console.log('skReq (Session key request for cached keys that will be used by clients) command');
            var numKeys = 3;
            if (message != undefined) {
                numKeys = parseInt(message);
            }
            // specify auth ID as a value
            sendSessionKeyRequest({cachedKeys: 101}, numKeys, {targetSessionKeyCache: 'Clients'});
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
        else if (command == 'bcSub') {
            console.log('broadcasting subscription command');
            initBroadcastingSubscription();
        }
        else if (command == 'send') {
            console.log('send command');
            if (message == undefined) {
                console.log('no message!');
                return;
            }
            sendToClients(new Buffer(message));
        }
        else if (command == 'sendFile') {
            console.log('sendFile command');
            var fileName = '../data_examples/data.bin';
            if (message != undefined) {
                fileName = message;
            }
            console.error('======== log for experiments: publishing message =========');
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
    var entityInfo = secureCommServer.getEntityInfo();
    console.log(entityInfo.name + ':' + entityInfo.group + ' prompt>');
};

process.stdin.on('readable', commandInterpreter);

