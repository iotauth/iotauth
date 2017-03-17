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
 * SecurePublisher accessor for accessing Auth services and publishing/broadcasting messages.
 * @author Hokeun Kim
 */
"use strict";

var fs = require('fs');
var iotAuth = require('iotAuth');
var mqtt = require('mqtt');
var util = require('util');
var msgType = iotAuth.msgType;

// to be loaded from config file
var entityConfig;
var currentDistributionKey;

var currentSessionKeyList = [];
var currentSessionKey;

var mqttClient = null;
var broadcastingSocket = null;
var pubSeqNum = 0;

var parameters =  {
    numKeysPerRequest: 1,
    topic: null
};
var outputs = {};
var outputHandlers = {};

// constructor
function SecurePublisher(configFilePath) {
    entityConfig = iotAuth.loadEntityConfig(configFilePath);
}

function onConnection(info) {
    outputs.connection = info;
    if (outputHandlers.connection) {
        outputHandlers.connection(info);
    }
    if (currentSessionKeyList.length > 0) {
        onReady('publisher is ready');
    }
}

function onError(message) {
    outputs.error = message;
    if (outputHandlers.error) {
        outputHandlers.error(message);
    }
}

function onReady(info) {
    outputs.ready = info;
    if (outputHandlers.ready) {
        outputHandlers.ready(info);
    }
}

function handleSessionKeyResp(sessionKeyList, receivedDistKey, callbackParams) {
    if (receivedDistKey != null) {
        console.log('updating distribution key: ' + util.inspect(receivedDistKey));
        currentDistributionKey = receivedDistKey;
    }
    console.log('received ' + sessionKeyList.length + ' keys');
    if (callbackParams.targetSessionKeyCache == 'Publish') {
        currentSessionKeyList = currentSessionKeyList.concat(sessionKeyList);
        if (mqttClient || broadcastingSocket) {
        onReady('publisher is ready');
        }
    }
    else {
        console.log('Error! communication target is wrong!');
    }
};

function sendSessionKeyRequest(purpose, numKeys, sessionKeyRespCallback, callbackParams) {
    var options = iotAuth.getSessionKeyReqOptions(entityConfig, currentDistributionKey, purpose, numKeys);
    var eventHandlers = {
        onError: onError
    };
    iotAuth.sendSessionKeyReq(options, sessionKeyRespCallback, eventHandlers, callbackParams);
};

function initBroadcastingPublish() {
    var dgram = require('dgram'); 
    broadcastingSocket = dgram.createSocket("udp4"); 
    broadcastingSocket.on('listening', function(){
        broadcastingSocket.setBroadcast(true);
        //broadcastingSocket.setMulticastTTL(128);
        //broadcastingSocket.addMembership('230.185.192.108'); 
        var address = broadcastingSocket.address();
        onConnection('started udp socket for broadcasting at ' + address.address + ':' + address.port);
    });
    broadcastingSocket.on('error', function(error) {
        onError('UDP broadcasting socket has an error! :' + error);
    });
    broadcastingSocket.bind();
    return;
}

function mqttPublish() {
    // ping request period 600 seconds
    mqttClient = mqtt.connect('mqtt://localhost', {keepalive: 600});
    mqttClient.on('connect', function () {
        onConnection('connected to the mqtt broker! from local port ' + mqttClient.stream.localPort);
    });
    mqttClient.on('error', function (error) {
        onError('MQTT client has an error! :' + error);
    });
    mqttClient.on('close', function () {
        onError('MQTT client has been closed!');
    });
}

function sendSecurePublish(data, protocol) {
    if (currentSessionKeyList.length == 0) {
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
            {seqNum: pubSeqNum, data: data}, currentSessionKeyList[0], entityConfig.cryptoInfo.sessionCryptoSpec);
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
            {seqNum: pubSeqNum, data: data}, currentSessionKeyList[0], entityConfig.cryptoInfo.sessionCryptoSpec);
        pubSeqNum++;
        broadcastingSocket.send(secureMqtt, 0, secureMqtt.length, 8088, BROADCAST_ADDR);
        console.log("Sent " + data.toString() + " to the wire...");

    }
    else {
        console.eror('unrecognized protocol! ' + protocol);
    }
};

function toPublishInputHandler(toPublish) {
    sendSecurePublish(toPublish, entityConfig.entityInfo.distProtocol);
}

//////// Main interfaces

SecurePublisher.prototype.initialize = function() {
    mqttClient = null;
    broadcastingSocket = null;
    console.log('initializing... Protocol: ' + entityConfig.entityInfo.distProtocol);
    if (entityConfig.entityInfo.usePermanentDistKey) {
        currentDistributionKey = entityConfig.entityInfo.permanentDistKey;
    }
    else {
        currentDistributionKey = null;
    }
    if (entityConfig.entityInfo.distProtocol == 'TCP') {
        mqttPublish();
    }
    else if (entityConfig.entityInfo.distProtocol == 'UDP') {
        initBroadcastingPublish();
    }
    else {
        throw 'failed to initialize! unrecognized protocol: ' + entityConfig.entityInfo.distProtocol;
    }
    outputs = {
        connection: null,
        error: null,
        ready: null
    };
    outputHandlers = {
        connection: null,
        error: null,
        ready: null
    };
    console.log('current parameters: ' + util.inspect(parameters));
    sendSessionKeyRequest({pubTopic: parameters.topic}, parameters.numKeysPerRequest, handleSessionKeyResp,
        {targetSessionKeyCache: 'Publish'});
}

SecurePublisher.prototype.provideInput = function(port, input) {
    if (port == 'toPublish') {
        toPublishInputHandler(input);
    }
}

SecurePublisher.prototype.setParameter = function(key, value) {
    parameters[key] = value;
}

SecurePublisher.prototype.latestOutput = function(key) {
    return outputs[key];
}

SecurePublisher.prototype.setOutputHandler = function(key, handler) {
    return outputHandlers[key] = handler;
}

//////// Supportive interfaces

SecurePublisher.prototype.getEntityInfo = function() {
    return entityConfig.entityInfo;
}

SecurePublisher.prototype.showKeys = function() {
    var result = '';
    result += 'distribution key: '+ util.inspect(currentDistributionKey) + '\n';
    result += 'Session keys for Servers: \n';
    result += util.inspect(currentSessionKeyList) + '\n';
    return result;
}

SecurePublisher.prototype.showSocket = function() {
    var result = '';
    if (mqttClient) {
        result += 'mqttClient:\n';
        result += util.inspect(mqttClient) + '\n';
    }
    if (broadcastingSocket) {
        result += 'broadcastingSocket:\n';
        result += util.inspect(broadcastingSocket) + '\n';
    }
    return result;
}

module.exports = SecurePublisher;