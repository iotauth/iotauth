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
 * Example client entity.
 * @author Hokeun Kim
 */
"use strict";

var net = require('net');
var fs = require('fs');
var entityCommon = require('./common/entityCommon')
var common = require('./common/common');
var mqtt = require('mqtt');
var util = require('util');
var msgType = common.msgType;
var commState = entityCommon.commState;

// to be loaded from config file
var entityInfo;
var authInfo;
var targetServerInfoList;

// initial states
var currentState = commState.IDLE;
var pubSeqNum = 0;
var writeSeqNum = 0;
var readSeqNum = 0;

// session keys
var sessionKeyCacheForServers = [];
var sessionKeyCacheForPublish = [];
var currentTargetSessionKeyCache;

// distributionKey = {val: Buffer, absValidity: Date() format}
var distributionKey = null;

function handleSessionKeyResp(sessionKeyList, receivedDistKey) {
    if (receivedDistKey != null) {
        console.log('updating distribution key: ' + util.inspect(receivedDistKey));
        distributionKey = receivedDistKey;
    }
    console.log('received ' + sessionKeyList.length + ' keys');
    if (currentTargetSessionKeyCache == 'Servers') {
    	sessionKeyCacheForServers = sessionKeyCacheForServers.concat(sessionKeyList);
    }
    else if (currentTargetSessionKeyCache == 'Publish') {
    	sessionKeyCacheForPublish = sessionKeyCacheForPublish.concat(sessionKeyList);
    }
};

var commSessionKey;
var curClient;
var tempLargeDataBuf;

function initComm(commServerInfo) {
    if (sessionKeyCacheForServers.length == 0) {
        console.log('No available key for servers!');
        return;
    }

    // per connection information
    commSessionKey = sessionKeyCacheForServers[0];
    console.log('chosen commSessionKey: ');
    console.log(commSessionKey);
    var myNonce;

    curClient = net.connect({host:commServerInfo.host, port: commServerInfo.port},
        function() {
            console.log('connected to ' + commServerInfo.name + '(' + commServerInfo.host
                + ':' + commServerInfo.port + ')! from local port ' + curClient.localPort);

            myNonce = entityCommon.generateHSNonce();
            console.log('chosen nonce: ' + myNonce.inspect());

            var handshake1 = {nonce: myNonce};
            var buf = entityCommon.serializeHandshake(handshake1);
            var enc = entityCommon.encryptSessionMessage(buf, commSessionKey.val);
            var keyIdBuf = new Buffer(common.S_KEY_ID_SIZE);
            keyIdBuf.writeUIntBE(commSessionKey.id, 0, common.S_KEY_ID_SIZE);

            var msg = {
                msgType: msgType.SKEY_HANDSHAKE_1,
                payload: Buffer.concat([keyIdBuf, enc])
            };
            curClient.write(common.serializeIoTSP(msg));

            console.log('switching to HANDSHAKE_1_SENT');
            currentState = commState.HANDSHAKE_1_SENT;
    });

    var expectingMoreData = false;
    var obj;
    curClient.on('data', function(data) {
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
        else if (obj.msgType == msgType.SKEY_HANDSHAKE_2) {
            console.log('received session key handshake2!');
            if (currentState != commState.HANDSHAKE_1_SENT) {
                console.log('Error: wrong sequence of handshake, disconnecting...');
                currentState = commState.IDLE;
                curClient.end();
                return;
            }

            var buf = entityCommon.decryptSessionMessage(obj.payload, commSessionKey.val);
            var ret = entityCommon.parseHandshake(buf);
            console.log(ret);

            if (myNonce.equals(ret.replyNonce)) {
                console.log('server authenticated/authorized by solving nonce!');
            }
            else {
                console.log('Error: server NOT verified, nonce NOT matched, disconnecting...');
                currentState = commState.IDLE;
                curClient.end();
                return;
            }

            var theirNonce = ret.nonce;
            var handshake3 = {replyNonce: theirNonce};

            buf = entityCommon.serializeHandshake(handshake3);
            var enc = entityCommon.encryptSessionMessage(buf, commSessionKey.val);

            var msg = {
                msgType: msgType.SKEY_HANDSHAKE_3,
                payload: enc
            };
            curClient.write(common.serializeIoTSP(msg));

            console.log('switching to IN_COMM');
            currentState = commState.IN_COMM;
            readSeqNum = 0;
            writeSeqNum = 0;
        }
        else if (obj.msgType == msgType.SECURE_COMM_MSG) {
            console.log('received secure communication message!');
            if (currentState != commState.IN_COMM) {
                console.log('Error: it is not in IN_COMM state, disconecting...');
                currentState = commState.IDLE;
                curClient.end();
                return;
            }

            var ret = entityCommon.parseDecryptSessionMessage(obj.payload, commSessionKey.val);
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

    curClient.on('end', function() {
        console.log('disconnected from ' + commServerInfo.name);
        console.log('switching to IDLE');
        currentState = commState.IDLE;
    });
    curClient.on('error', function(message) {
        console.log('Error, details: ' + message);
    });
};

function finComm() {
    curClient.end();
    currentState = commState.IDLE;
    // remove used session key
    for (var i = 0; i < sessionKeyCacheForServers.length; i++) {
        if (sessionKeyCacheForServers[i].id == commSessionKey.id) {
            sessionKeyCacheForServers.splice(i, 1);
        }
    }
};

var mqttClient;

function commandInterpreter() {
    var chunk = process.stdin.read();
    if (chunk != null) {
        var input = chunk.toString().trim();
        var idx = input.indexOf(' ');
        var command;
        var message = undefined;
        if (idx < 0) {
            command = input;
        }
        else {
            command = input.slice(0, idx);
            message = input.slice(idx + 1);
        }

        if (command == 'initComm') {
            if (currentState != commState.IDLE) {
                console.log('invalid initComm command, it is not in IDLE state');
                return;
            }
            var commServerInfo = null;
            if (message != undefined) {
                var tokens = message.split(' ');
                var serverName = tokens[0];

                for (var i = 0; i < targetServerInfoList.length; i++) {
                    if (targetServerInfoList[i].name == serverName) {
                        commServerInfo = targetServerInfoList[i];
                    }
                }
                if (commServerInfo == null) {
                    console.log('cannot find communication server named ' + serverName);
                    return;
                }

                if (tokens.length > 1) {
                    var serverPort = parseInt(tokens[1]);
                    console.log('serverPort is explicitly specified: ' + serverPort);
                    commServerInfo.port = serverPort;
                }
            }
            else {
                commServerInfo = targetServerInfoList[0];
            }
            
            console.log('initComm command targeted to ' + commServerInfo.name);
            initComm(commServerInfo);
        }
        else if (command == 'finComm' || command == 'f') {
            if (currentState != commState.IN_COMM) {
                console.log('invalid finComm command, it is not in IN_COMM state');
            }
            else {
                console.log('finComm command');
                finComm();
            }
        }
        else if (command == 'showKeys') {
            console.log('showKeys command. distribution key and session keys: ');
            console.log('distribution key: '+ util.inspect(distributionKey));
            console.log('Session keys for Servers: ');
            console.log(util.inspect(sessionKeyCacheForServers));
            console.log('Session keys for Publish: ');
            console.log(util.inspect(sessionKeyCacheForPublish));
        }
        else if (command == 'send') {
            if (currentState != commState.IN_COMM) {
                console.log('invalid send command, it is not in IN_COMM state');
            }
            else {
                console.log('send command');
                var enc = entityCommon.serializeEncryptSessionMessage(
                	{seqNum: writeSeqNum, data: new Buffer(message)}, commSessionKey.val);
                writeSeqNum++;
                var buf = common.serializeIoTSP({
                    msgType: msgType.SECURE_COMM_MSG,
                    payload: enc
                });
                curClient.write(buf);
            }
        }
        else if (command == 'sendFile') {
            if (currentState != commState.IN_COMM) {
                console.log('invalid sendFile command, it is not in IN_COMM state');
            }
            else {
                console.log('sendFile command');
                var fileName = '../data_examples/data.bin';
                if (message != undefined) {
                    fileName = message;
                }
                var fileData = fs.readFileSync(fileName);
                console.log('file data length: ' + fileData.length);
                var enc = entityCommon.serializeEncryptSessionMessage(
                	{seqNum: writeSeqNum, data: fileData}, commSessionKey.val);
                writeSeqNum++;
                var buf = common.serializeIoTSP({
                    msgType: msgType.SECURE_COMM_MSG,
                    payload: enc
                });
                curClient.write(buf);
            }
        }
        else if (command == 'mqtt') {
            console.log('mqtt command, init mqtt connection');

            // ping request period 600 seconds
            mqttClient = mqtt.connect('mqtt://localhost', {keepalive: 600});
            mqttClient.on('connect', function () {
                console.log('connected to the mqtt broker! from local port '
                    + mqttClient.stream.localPort);
            });
        }
        else if (command == 'pub') {
            console.log('pub command, INSECURE publish');
            if (mqttClient == undefined) {
                console.log('mqttClient is not initialized!');
                return;
            }
            if (message == undefined) {
                console.log('no message!');
                return;
            }
            mqttClient.publish('Ptopic', message);
        }
        else if (command == 'spub') {
            console.log('spub command, secure publish');
            if (mqttClient == undefined) {
                console.log('mqttClient is not initialized!');
                return;
            }
            if (sessionKeyCacheForPublish.length == 0) {
                console.log('no available keys for publish!');
                return;
            }
            if (message == undefined) {
                console.log('no message!');
                return;
            }
            var secureMqtt = entityCommon.encryptSerializeSecureqMqtt(
                {seqNum: pubSeqNum, data: new Buffer(message)}, sessionKeyCacheForPublish[0]);
            pubSeqNum++;
            var buf = common.serializeIoTSP({
                msgType: msgType.SECURE_PUB,
                payload: secureMqtt
            });
            mqttClient.publish('Ptopic', buf);
        }
        else if (command == 'spubFile') {
            console.log('spubFile command, secure publish of file');
            if (mqttClient == undefined) {
                console.log('mqttClient is not initialized!');
                return;
            }
            if (sessionKeyCacheForPublish.length == 0) {
                console.log('no available keys!');
                return;
            }
            var fileName = '../data_examples/data.bin';
            if (message != undefined) {
                fileName = message;
            }
            var fileData = fs.readFileSync(fileName);
            console.log('file data length: ' + fileData.length);
            var secureMqtt = entityCommon.encryptSerializeSecureqMqtt(
                {seqNum: pubSeqNum, data: fileData}, sessionKeyCacheForPublish[0]);
            pubSeqNum++;
            var buf = common.serializeIoTSP({
                msgType: msgType.SECURE_PUB,
                payload: secureMqtt
            });
            mqttClient.publish('Ptopic', buf);
        }
        else if (command == 'skReq') {
            console.log('skReq (Session key request for target servers) command');
            var numKeys = 3;
            if (message != undefined) {
                numKeys = parseInt(message);
            }
            currentTargetSessionKeyCache = 'Servers';
            entityCommon.sendSessionKeyReq(entityInfo.name, {group: 'Servers'}, numKeys,
                authInfo, entityInfo.privateKey, distributionKey, handleSessionKeyResp);
        }
        else if (command == 'skReq2') {
            console.log('skReq2 (Session key request for existing session keys for target servers) command');
            var numKeys = 3;
            if (message != undefined) {
                numKeys = parseInt(message);
            }
            currentTargetSessionKeyCache = 'Servers';
            entityCommon.sendSessionKeyReq(entityInfo.name, {group: 'Servers', exist: true}, numKeys,
                authInfo, entityInfo.privateKey, distributionKey, handleSessionKeyResp);
        }
        else if (command == 'skReqPub') {
            console.log('skReqPub (Session key request for target publish topic) command');
            var numKeys = 3;
            if (message != undefined) {
                numKeys = parseInt(message);
            }
            currentTargetSessionKeyCache = 'Publish';
            entityCommon.sendSessionKeyReq(entityInfo.name, {pubTopic: 'Ptopic'}, numKeys,
                authInfo, entityInfo.privateKey, distributionKey, handleSessionKeyResp);
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
        else if (command == 'exp1') {
            console.log('experiment for scenario 1 command!');
            if (message == undefined) {
                console.log('specify number of servers!');
                return;
            }
            var serverCount = parseInt(message);
            console.log('start experiments for ' + serverCount + ' servers');
            var idx = 0;
            commServerInfo = {name: 'net1.Server', host: 'localhost', port: 21100};
            var repeater;
            var repeater2;
            var repeater2 = function() {
                finComm();
                commServerInfo.port++;
                idx++;
                if (idx < serverCount) {
                    setTimeout(repeater, 1000);
                }
            }
            var repeater = function() {
                initComm(commServerInfo);
                setTimeout(repeater2, 1000);
            }
            repeater();
        }
        else if (command == 'exp2') {
            console.log('exp2 command, experiment setup for scenario 2 without broker');
            console.log('requesting 1 existing key & connect to server');
            function handleSessionKeyRespWrapper(sessionKeyList, receivedDistKey) {
                handleSessionKeyResp(sessionKeyList, receivedDistKey);
                var commServerInfo = targetServerInfoList[0];
                console.log('initComm command targeted to ' + commServerInfo.name);
                initComm(commServerInfo);
            }
            var numKeys = 1;
            currentTargetSessionKeyCache = 'Servers';
            entityCommon.sendSessionKeyReq(entityInfo.name, {subTopic: 'Ptopic'}, numKeys,
                authInfo, entityInfo.privateKey, distributionKey, handleSessionKeyRespWrapper);

        }
        else {
            console.log('unrecognized command: ' + command);
        }
    }
    console.log(entityInfo.name + ':' + entityInfo.group + ' prompt>');
};

var configFilePath = 'configs/net1/client.config';
if (process.argv.length > 2) {
    configFilePath = process.argv[2];
}

var entityConfig = entityCommon.loadEntityConfig(configFilePath);

entityInfo = entityConfig.entityInfo;
authInfo = entityConfig.authInfo;
targetServerInfoList = entityConfig.targetServerInfoList;

process.stdin.on('readable', commandInterpreter);
