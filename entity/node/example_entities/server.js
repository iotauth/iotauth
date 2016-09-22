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

var net = require('net');
var fs = require('fs');
var iotAuth = require('iotAuth')
var common = require('common');
var mqtt = require('mqtt');
var util = require('util');
var msgType = iotAuth.msgType;
var commState = {
    IDLE: 0,
    HANDSHAKE_1_SENT: 1,
    HANDSHAKE_2_SENT: 2,
    HANDSHAKE_3_SENT: 3,
    IN_COMM: 4                    // Session message
};

// to be loaded from config file
var entityInfo;
var authInfo;
var listeningServerInfo;

// initial states
var currentState = commState.IDLE;
var writeSeqNum = 0;
var readSeqNum = 0;

// session keys
var sessionKeyCacheForClients = [];
var sessionKeyCacheForSubscribe = [];
var currentTargetSessionKeyCache;

// distributionKey = {val: Buffer, absValidity: Date() format}
var distributionKey = null;

function handleSessionKeyResp(sessionKeyList, receivedDistKey) {
    if (receivedDistKey != null) {
        console.log('updating distribution key: ' + util.inspect(receivedDistKey));
        distributionKey = receivedDistKey;
    }
    console.log('received ' + sessionKeyList.length + ' keys');
    if (currentTargetSessionKeyCache == 'Clients') {
    	sessionKeyCacheForClients = sessionKeyCacheForClients.concat(sessionKeyList);
    }
    else if (currentTargetSessionKeyCache == 'Subscribe') {
    	sessionKeyCacheForSubscribe = sessionKeyCacheForSubscribe.concat(sessionKeyList);
    }
};

var connectedClients = [];
var lastActiveSessionKey = undefined;
var tempLargeDataBuf;

var server = net.createServer(function(connection) {
    console.log('Unidentified client connected');
    connection.on('end', function() {
        console.log('Unidentified client disconnected');
    });

    var myNonce;
    var sessionKey = undefined;
    var obj;
    var keyId;

    function sendHandshake2(sessionKeyList, receivedDistKey) {
        handleSessionKeyResp(sessionKeyList, receivedDistKey);
        // sessionKey derived from call back
        if (sessionKey == undefined) {
            for (var i = 0; i < sessionKeyCacheForClients.length; i++) {
                if (sessionKeyCacheForClients[i].id == keyId) {
                    console.log('found session key inside callback');
                    sessionKey = sessionKeyCacheForClients[i];
                    break;
                }
            }
        }

        var enc = obj.payload.slice(common.S_KEY_ID_SIZE);
        var buf = iotAuth.decryptSessionMessage(enc, sessionKey.val);

        var ret = iotAuth.parseHandshake(buf);
        var theirNonce = ret.nonce;

        console.log(ret);

        myNonce = iotAuth.generateHSNonce();
        console.log('chosen nonce: ' + myNonce.inspect());
        var handshake2 = {nonce: myNonce, replyNonce: theirNonce};
        buf = iotAuth.serializeHandshake(handshake2);
        enc = iotAuth.encryptSessionMessage(buf, sessionKey.val);
        var msg = {
            msgType: msgType.SKEY_HANDSHAKE_2,
            payload: enc
        };
        connection.write(common.serializeIoTSP(msg));
        console.log('switching to HANDSHAKE_2_SENT');
        currentState = commState.HANDSHAKE_2_SENT;
    }

    var expectingMoreData = false;
    connection.on('data', function(data) {
        if (!expectingMoreData) {
            obj = common.parseIoTSP(data);
            if (obj.payload.length < obj.payloadLen) {
                expectingMoreData = true;
                console.log('more data will come. current: ' + obj.payload.length
                    + ' expected: ' + obj.payloadLen);
            }
        }
        else {
            obj.payload = Buffer.concat([obj.payload, data]);
            if (obj.payload.length ==  obj.payloadLen) {
                expectingMoreData = false;
            }
            else {
                console.log('more data will come. current: ' + obj.payload.length
                    + ' expected: ' + obj.payloadLen);
            }
        }

        if (expectingMoreData) {
            // do not process the packet yet
            return;
        }
        else if (obj.msgType == msgType.SKEY_HANDSHAKE_1) {
            console.log('received session key handshake1');
            keyId = obj.payload.readUIntBE(0, common.S_KEY_ID_SIZE);
            console.log('session key id: ' + keyId);

            var sessionKeyFound = false;
            for (var i = 0; i < sessionKeyCacheForClients.length; i++) {
                if (sessionKeyCacheForClients[i].id == keyId) {
                    console.log('found session key');
                    sessionKey = sessionKeyCacheForClients[i];
                    sessionKeyFound = true;
                    break;
                }
            }
            if (sessionKeyFound) {
                // send empty list
                sendHandshake2([]);
            }
            else {
                console.log('session key NOT found! sending session key request');
                currentTargetSessionKeyCache = 'Clients';
                iotAuth.sendSessionKeyReq(entityInfo.name, {keyId: keyId}, 1,
                    authInfo, entityInfo.privateKey, distributionKey, sendHandshake2);
            }
        }
        else if (obj.msgType == msgType.SKEY_HANDSHAKE_3) {
            console.log('received session key handshake3!');
            if (currentState != commState.HANDSHAKE_2_SENT) {
                console.log('Error: wrong sequence of handshake, disconnecting...');
                currentState = commState.IDLE;
                connection.end();
                return;
            }
            var buf = iotAuth.decryptSessionMessage(obj.payload, sessionKey.val);
            var ret = iotAuth.parseHandshake(buf);
            console.log(ret);

            if (myNonce.equals(ret.replyNonce)) {
                console.log('client authenticated/authorized by solving nonce!');
            }
            else {
                console.log('Error: client NOT verified, nonce NOT matched, disconnecting...');
                currentState = commState.IDLE;
                client.end();
                return;
            }

            console.log('switching to IN_COMM');
            currentState = commState.IN_COMM;
            writeSeqNum = 0;
            readSeqNum = 0;

            // registering clients as potential subscribers
            connectedClients.push(connection);
            lastActiveSessionKey = sessionKey;
        }
        else if (obj.msgType == msgType.SECURE_COMM_MSG) {
            console.log('received secure communication!');
            if (currentState != commState.IN_COMM) {
                console.log('Error: it is not in IN_COMM state, disconecting...');
                currentState = commState.IDLE;
                connection.end();
                return;
            }

            var ret = iotAuth.parseDecryptSessionMessage(obj.payload, sessionKey.val);
            if (ret.seqNum != readSeqNum) {
            	console.log('seqNum does not match! expected: ' + readSeqNum + ' received: ' + ret.seqNum);
            }
            readSeqNum++;
            if (ret.data.length > 65535) {
            	console.log('seqNum: ' + ret.seqNum);
                console.log('data is too large to display, to store in file use saveData command');
                tempLargeDataBuf = ret.data;
            }
            else {
            	console.log('seqNum: ' + ret.seqNum + ' data: ' + ret.data.toString());
            }
        }
    });
});

function sendToClients(message) {
    if (lastActiveSessionKey == undefined) {
        console.log('no session key for clients')
        return;
    }
    if (connectedClients.length == undefined) {
        console.log('no connected clients')
        return;
    }
    var enc = iotAuth.serializeEncryptSessionMessage(
    	{seqNum: writeSeqNum, data: new Buffer(message)}, lastActiveSessionKey.val);
    writeSeqNum++;
    var buf = common.serializeIoTSP({
        msgType: msgType.SECURE_COMM_MSG,
        payload: enc
    });
    for (var i = 0; i < connectedClients.length; i++) {
    	try{
        	connectedClients[i].write(buf);
    	}
    	catch (err) {
    		console.log('error while sending to client: ' + err.message);
    		console.log('removing this client from the list...');
    		connectedClients.splice(i, 1);
    		i--;
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
}

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
            currentTargetSessionKeyCache = 'Subscribe';
            iotAuth.sendSessionKeyReq(entityInfo.name, {subTopic: 'Ptopic'}, numKeys,
                authInfo, entityInfo.privateKey, distributionKey, handleSessionKeyResp);
        }
        else if (command == 'skReqPub') {
            console.log('skReqSub (Session key request for target publish topic) command');
            var numKeys = 1;
            if (message != undefined) {
                numKeys = parseInt(message);
            }
            currentTargetSessionKeyCache = 'Clients';
            iotAuth.sendSessionKeyReq(entityInfo.name, {pubTopic: 'Ptopic'}, numKeys,
                authInfo, entityInfo.privateKey, distributionKey, handleSessionKeyResp);
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
            currentTargetSessionKeyCache = 'Subscribe';
            iotAuth.sendSessionKeyReq(entityInfo.name, {subTopic: 'Ptopic'}, numKeys,
                authInfo, entityInfo.privateKey, distributionKey, handleSessionKeyResp);
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

if (entityInfo.usePermanentDistKey) {
    var absValidity = new Date().getTime() + iotAuth.parseTimePeriod(entityInfo.distKeyValidity);
    distributionKey = {
        val: entityInfo.permanentDistKey,
        absValidity: new Date(absValidity)
    };
}

server.listen(listeningServerInfo.port, function() {
    console.log(entityInfo.name + ' bound on port ' + listeningServerInfo.port);
});

process.stdin.on('readable', commandInterpreter);

