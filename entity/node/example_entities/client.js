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

var fs = require('fs');
var iotAuth = require('iotAuth');
var mqtt = require('mqtt');
var util = require('util');
var msgType = iotAuth.msgType;

var clientCommState = {
    IDLE: 0,
    IN_COMM: 30                    // Session message
};

// to be loaded from config file
var entityInfo;
var authInfo;
var targetServerInfoList;
var cryptoInfo;

// initial states
var currentState = clientCommState.IDLE;
var pubSeqNum = 0;

// session keys
var sessionKeyCacheForServers = [];
var sessionKeyCacheForPublish = [];

// distributionKey = {val: Buffer, absValidity: Date() format}
var distributionKey = null;

function handleSessionKeyResp(sessionKeyList, receivedDistKey, callbackParams) {
    if (receivedDistKey != null) {
        console.log('updating distribution key: ' + util.inspect(receivedDistKey));
        distributionKey = receivedDistKey;
    }
    console.log('received ' + sessionKeyList.length + ' keys');
    if (callbackParams.targetSessionKeyCache == 'Servers') {
        sessionKeyCacheForServers = sessionKeyCacheForServers.concat(sessionKeyList);
    }
    else if (callbackParams.targetSessionKeyCache == 'Publish') {
        essionKeyCacheForPublish = sessionKeyCacheForPublish.concat(sessionKeyList);
    }
    else {
        console.log('Error! communication target is wrong!');
    }
    if (callbackParams.callback) {
        callbackParams.callback();
    }
};

var currentSessionKey;
var currentSecureClient;
var tempLargeDataBuf;


function finComm() {
    currentSecureClient.close();
    currentState = clientCommState.IDLE;
};

var mqttClient;
function onClose() {
    console.log('secure connection with the server closed.');
};
function onError(message) {
    console.error('Error in secure comm - details: ' + message);
};
function onData(data) {
    console.log('data received from server via secure communication');
    if (data.length > 65535) {
        console.log('data is too large to display, to store in file use saveData command');
        tempLargeDataBuf = data;
    }
    else {
        console.log(data.toString());
    }
};
function onConnection(entityClientSocket) {
    console.log('communication initialization succeeded');
    currentSecureClient = entityClientSocket;
    currentState = clientCommState.IN_COMM;
};

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
};

function sendSessionKeyRequest(purpose, numKeys, sessionKeyRespCallback, callbackParams) {
    var options = {
        authHost: authInfo.host,
        authPort: authInfo.port,
        entityName: entityInfo.name,
        numKeysPerRequest: numKeys,
        purpose: purpose,
        distProtocol: entityInfo.distProtocol,
        distributionKey: distributionKey,
        distributionCryptoSpec: cryptoInfo.distributionCryptoSpec,
        publicKeyCryptoSpec: cryptoInfo.publicKeyCryptoSpec,
        authPublicKey: authInfo.publicKey,
        entityPrivateKey: entityInfo.privateKey
    };
    iotAuth.sendSessionKeyReq(options, sessionKeyRespCallback, callbackParams);
};
var broadcastingSocket = null;
function initBroadcastingPublish() {
    var dgram = require('dgram'); 
    broadcastingSocket = dgram.createSocket("udp4"); 
    broadcastingSocket.on('listening', function(){
        broadcastingSocket.setBroadcast(true);
        //broadcastingSocket.setMulticastTTL(128);
        //broadcastingSocket.addMembership('230.185.192.108'); 
        var address = broadcastingSocket.address();
        console.log('started udp socket for broadcasting at ' + address.address + ':' + address.port);
    });
    broadcastingSocket.bind();
    return 
}




function sendSecurePublish(data, protocol) {
    if (sessionKeyCacheForPublish.length == 0) {
        console.log('no available keys for publish!');
        return;
    }
    console.error('======== log for experiments: publishing message =========');
    if (protocol === 'TCP') {
        if (mqttClient == undefined) {
            console.log('mqttClient is not initialized!');
            return;
        }
        var secureMqtt = iotAuth.encryptSerializeSecureqMqtt(
            {seqNum: pubSeqNum, data: data}, sessionKeyCacheForPublish[0], cryptoInfo.sessionCryptoSpec);
        pubSeqNum++;
        mqttClient.publish('Ptopic', secureMqtt);
    }
    else if (protocol === 'UDP') {
        console.log('with protocol ' + protocol + 'doing broadcast');
        if (broadcastingSocket == null) {
            console.error('broadcasting socket is not initialized!');
            return;
        }

        var MULTICAST_ADDR = '230.185.192.108';
        var BROADCAST_ADDR = '255.255.255.255';
        var secureMqtt = iotAuth.encryptSerializeSecureqMqtt(
            {seqNum: pubSeqNum, data: data}, sessionKeyCacheForPublish[0], cryptoInfo.sessionCryptoSpec);
        broadcastingSocket.send(secureMqtt, 0, secureMqtt.length, 8088, BROADCAST_ADDR);
        console.log("Sent " + data.toString() + " to the wire...");

    }
    else {
        console.eror('unrecognized protocol! ' + protocol);
    }
};

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
            if (currentState != clientCommState.IDLE) {
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
            initSecureCommWithSessionKey(sessionKeyCacheForServers.shift(), commServerInfo.host, commServerInfo.port);
        }
        else if (command == 'finComm' || command == 'f') {
            if (currentState != clientCommState.IN_COMM) {
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
        else if (command == 'showSocket') {
            console.log('showSocket command. current secure client socket: ');
            console.log(util.inspect(currentSecureClient));
            console.log('socket sessionKey:' + util.inspect(currentSecureClient.sessionKey));
        }
        else if (command == 'send') {
            if (currentState != clientCommState.IN_COMM) {
                console.log('invalid send command, it is not in IN_COMM state');
            }
            else {
                console.log('send command');
                currentSecureClient.send(new Buffer(message));
            }
        }
        else if (command == 'sendFile') {
            if (currentState != clientCommState.IN_COMM) {
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
                currentSecureClient.send(fileData);
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

            if (message == undefined) {
                console.log('no message!');
                return;
            }
            sendSecurePublish(new Buffer(message), entityInfo.distProtocol);
        }
        else if (command == 'spubFile') {
            console.log('spubFile command, secure publish of file');
            var fileName = '../data_examples/data.bin';
            if (message != undefined) {
                fileName = message;
            }
            var fileData = fs.readFileSync(fileName);
            console.log('file data length: ' + fileData.length);
            sendSecurePublish(fileData, entityInfo.distProtocol);
        }
        else if (command == 'skReq') {
            console.log('skReq (Session key request for target servers) command');
            var numKeys = 3;
            if (message != undefined) {
                numKeys = parseInt(message);
            }
            sendSessionKeyRequest({group: 'Servers'}, numKeys, handleSessionKeyResp,
                {targetSessionKeyCache: 'Servers'});
        }
        else if (command == 'skReq2') {
            console.log('skReq2 (Session key request for existing session keys for target servers) command');
            var numKeys = 3;
            if (message != undefined) {
                numKeys = parseInt(message);
            }
            sendSessionKeyRequest({group: 'Servers', exist: true}, numKeys, handleSessionKeyResp,
                {targetSessionKeyCache: 'Servers'});
        }
        else if (command == 'skReqPub') {
            console.log('skReqPub (Session key request for target publish topic) command');
            var numKeys = 3;
            if (message != undefined) {
                numKeys = parseInt(message);
            }
            sendSessionKeyRequest({pubTopic: 'Ptopic'}, numKeys, handleSessionKeyResp,
                {targetSessionKeyCache: 'Publish'});
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
        else if (command == 'initBc') {
            console.log('init UDP broadcasting command');
            initBroadcastingPublish();
        }
        else if (command == 'exp1') {
            console.log('experiment for scenario 1 command!');
            if (message == undefined) {
                console.log('specify number of servers!');
                return;
            }
            var args = message.split(' ');
            var serverCount = parseInt(args[0]);
            var serverPort = 22100;
            if (args.length > 1) {
                serverPort = parseInt(args[1]);
            }
            console.log('serverCount: ' + serverCount + ' serverPort: ' + serverPort);
            var numKeys = 1;
            console.log('start experiments for ' + serverCount + ' servers with ' + numKeys + ' per session key request');
            var idx = 0;
            commServerInfo = {name: 'net1.Server', host: 'localhost', port: serverPort};
            var repeater;
            var repeater2;
            var repeater2 = function() {
                finComm();
                //commServerInfo.port++;
                idx++;
                if (idx < serverCount) {
                    console.log('round ' + (idx + 1));
                    setTimeout(repeater, 500);
                }
            }
            var repeater = function() {
                if (sessionKeyCacheForServers.length == 0) {
                    sendSessionKeyRequest({group: 'Servers'}, numKeys, handleSessionKeyResp,
                        {targetSessionKeyCache: 'Servers', callback: repeater});
                }
                else {
                    initSecureCommWithSessionKey(sessionKeyCacheForServers.shift(), commServerInfo.host, commServerInfo.port);
                    setTimeout(repeater2, 500);
                }
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
                iotAuth.initializeSecureCommunication(commServerInfo);
            }
            var numKeys = 1;
            sendSessionKeyRequest({subTopic: 'Ptopic'}, numKeys, handleSessionKeyRespWrapper,
                {targetSessionKeyCache: 'Servers'});

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

var entityConfig = iotAuth.loadEntityConfig(configFilePath);

entityInfo = entityConfig.entityInfo;
authInfo = entityConfig.authInfo;
targetServerInfoList = entityConfig.targetServerInfoList;
cryptoInfo = entityConfig.cryptoInfo;

if (entityInfo.usePermanentDistKey) {
    distributionKey = entityInfo.permanentDistKey;
}

if (process.argv.length > 5) {
    var commandArg = process.argv[3];
    var serverPort = parseInt(process.argv[5]);
    function initCommExp2 () {
        initSecureCommWithSessionKey(sessionKeyCacheForServers.shift(), 'localhost', serverPort);
    }
    if (commandArg == 'exp2') {
        var keyId = parseInt(process.argv[4]);
        sendSessionKeyRequest({keyId: keyId}, 1, handleSessionKeyResp,
            {targetSessionKeyCache: 'Servers', callback: initCommExp2});
    }
}

process.stdin.on('readable', commandInterpreter);
