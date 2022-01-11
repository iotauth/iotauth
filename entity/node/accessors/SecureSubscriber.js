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
 * SecureSubscriber accessor for accessing Auth services and subscribing/listing to published/broadcasted messages.
 * @author Hokeun Kim
 */
"use strict";

var fs = require('fs');
var common = require('common');
var iotAuth = require('iotAuth');
var mqtt = require('mqtt');
var util = require('util');
var msgType = iotAuth.msgType;

// to be loaded from config file
var entityConfig;
var currentDistributionKey;

var currentSessionKeyList = [];
var currentTopic;

var mqttClient = null;
var udpListeningSocket = null;

var outputs = {};
var outputHandlers = {};

// constructor
function SecureSubscriber(configFilePath) {
	entityConfig = iotAuth.loadEntityConfig(configFilePath);
}

function handleSessionKeyResp(sessionKeyList, receivedDistKey, callbackParameters) {
    if (receivedDistKey != null) {
        console.log('updating distribution key: ' + util.inspect(receivedDistKey));
        currentDistributionKey = receivedDistKey;
    }
    console.log('received ' + sessionKeyList.length + ' keys');
    currentSessionKeyList = currentSessionKeyList.concat(sessionKeyList);

    if (callbackParameters.callback) {
        callbackParameters.callback(callbackParameters.topic, callbackParameters.message);
    }
}

function onError(message) {
    outputs.error = message;
    if (outputHandlers.error) {
        outputHandlers.error(message);
    }
}

function sendSessionKeyRequest(purpose, numKeys, callbackParams) {
    var options = iotAuth.getSessionKeyReqOptions(entityConfig, currentDistributionKey, purpose, numKeys);
    var eventHandlers = {
        onError: onError
    };
    iotAuth.sendSessionKeyReq(options, handleSessionKeyResp, eventHandlers, callbackParams);
};

function processData(buf, sessionKey, topic) {
    var ret = iotAuth.parseDecryptSecureMqtt(buf,
    	[sessionKey], entityConfig.cryptoInfo.sessionCryptoSpec);
    outputs.received = ret.data;
    outputs.receivedTopic = currentTopic;
	console.log('seqNum: ' + ret.seqNum);
    if (outputHandlers.received) {
    	outputHandlers.received({data: ret.data, topic: topic});
    }
}

function onData(topic, message) {
    var obj = common.parseIoTSP(message);
    if (obj.msgType == msgType.SECURE_PUB) {
        console.log('received secure pub!');
    	var keyId = common.readVariableUIntBE(obj.payload, 0, common.SESSION_KEY_ID_SIZE);

    	for (var i = 0; i < currentSessionKeyList.length; i++) {
        	if (currentSessionKeyList[i].id == keyId) {
        		processData(obj.payload, currentSessionKeyList[i], topic);
        		return;
    		}
    	}
        console.log('session key NOT found! sending session key id to AuthService');
        var callbackParameters = {
        	callback: onData,
        	topic: topic,
        	message: message
        };
        sendSessionKeyRequest({keyId: keyId}, 1, callbackParameters);
    }
    else {
        console.log('received unexpected message that is not SECURE_PUB!');
    }
}

function initMqttSubscribe(topic) {
    // ping request period 600 seconds
    mqttClient = mqtt.connect('mqtt://localhost', {keepalive: 600});
    mqttClient.on('connect', function () {
        console.log('connected to the mqtt broker, started subscribing from local port '
                    + mqttClient.stream.localPort);
        mqttClient.subscribe(topic);
    });
    mqttClient.on('message', function (topic, message) {
        console.log('received a mqtt message!');
        onData(topic, message);
    });
    mqttClient.on('error', function (error) {
        onError('MQTT client has an error! :' + error);
    });
    mqttClient.on('close', function () {
        onError('MQTT client has been closed!');
    });
};

function initBroadcastingSubscription(broadcastingPort) {
    //var PORT = 8088;
    //var HOST = 'localhost';
    //var MULTICAST_ADDR = multicastAddr;
    var dgram = require('dgram');
    udpListeningSocket = dgram.createSocket('udp4');

    udpListeningSocket.on('listening', function () {
        var address = udpListeningSocket.address();
        console.log('UDP Client listening on ' + broadcastingPort);
        udpListeningSocket.setBroadcast(true);
        //client.setMulticastTTL(128); 
        //client.addMembership(MULTICAST_ADDR);
    });

    udpListeningSocket.on('message', function (message, remote) {   
        console.log('A: Epic Command Received. Preparing Relay.');
        console.log('B: From: ' + remote.address + ':' + remote.port);
		onData(null, message);
    });

    udpListeningSocket.on('error', function(error) {
        onError('UDP subscription socket has an error! :' + error);
    });

    udpListeningSocket.bind(broadcastingPort);
};

function subscribeInputHandler(topic) {
	var info = null;
    if (entityConfig.entityInfo.distProtocol == 'TCP') {
        initMqttSubscribe(topic);
        info = 'subscribed on topic: ' + topic;
    }
    else if (entityConfig.entityInfo.distProtocol == 'UDP') {
        initBroadcastingSubscription(topic);
        info = 'started listening to udp broadcast on multicast addr:port - ' + topic;
    }
    else {
    	throw 'unrecognized protocol!' + entityConfig.entityInfo.distProtocol;
    }
    outputs.subscription = info;
    if (outputHandlers.subscription) {
    	outputHandlers.subscription(info);
    }
}

function unsubscribeInputHandler(topic) {
	var info = 'nothing to unsubscribe';
    if (entityConfig.entityInfo.distProtocol == 'TCP') {
        if (mqttClient) {
        	mqttClient.unsubscribe(topic);
        	info = 'unsubscribed from topic: ' + topic;
        }
    }
    else if (entityConfig.entityInfo.distProtocol == 'UDP') {
		if (udpListeningSocket) {
			var socketAddr = udpListeningSocket.address();
			udpListeningSocket.close();
			udpListeningSocket = null;
        	info = 'unsubscribed from multicast socket: ' + socketAddr;
		}
	}
    else {
    	throw 'unrecognized protocol!' + entityConfig.entityInfo.distProtocol;
    }
    outputs.subscription = info;
    if (outputHandlers.subscription) {
    	outputHandlers.subscription(info);
    }
}

//////// Main interfaces

SecureSubscriber.prototype.initialize = function() {
    mqttClient = null;
    udpListeningSocket = null;
    console.log('initializing... Protocol: ' + entityConfig.entityInfo.distProtocol);
    if (entityConfig.entityInfo.usePermanentDistKey) {
        currentDistributionKey = entityConfig.entityInfo.permanentDistKey;
    }
    else {
        currentDistributionKey = null;
    }
    outputs = {
        connection: null,
        subscription: null,
        received: null,
        receivedTopic: null
    };
    outputHandlers = {
        connection: null,
        subscription: null,
        received: null			// this also outputs subscription topic for simplicity, i.e., received = {data: buffer, topic: subscriptionTopic}
    };
}

SecureSubscriber.prototype.provideInput = function(port, input) {
    if (port == 'subscribe') {
        subscribeInputHandler(input);
    }
    else if (port == 'unsubscribe') {
        unsubscribeInputHandler(input);
    }
}

SecureSubscriber.prototype.latestOutput = function(key) {
    return outputs[key];
}

SecureSubscriber.prototype.setOutputHandler = function(key, handler) {
    return outputHandlers[key] = handler;
}


//////// Supportive interfaces

SecureSubscriber.prototype.getEntityInfo = function() {
    return entityConfig.entityInfo;
}

SecureSubscriber.prototype.showKeys = function() {
    var result = '';
    result += 'distribution key: '+ util.inspect(currentDistributionKey) + '\n';
    result += 'Session keys for Servers: \n';
    result += util.inspect(currentSessionKeyList) + '\n';
    return result;
}

SecureSubscriber.prototype.showSocket = function() {
    var result = '';
    if (mqttClient) {
        result += 'mqttClient:\n';
        result += util.inspect(mqttClient) + '\n';
    }
    if (udpListeningSocket) {
        result += 'udpListeningSocket:\n';
        result += util.inspect(udpListeningSocket) + '\n';
    }
    return result;
}

module.exports = SecureSubscriber;
