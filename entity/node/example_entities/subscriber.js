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
 * Example subscriber entity written using SecureSubscriber accessor.
 * @author Hokeun Kim
 */
"use strict";

var fs = require('fs');
var SecureSubscriber = require('../accessors/SecureSubscriber');

function connectionHandler(info) {
    console.log('Handler: ' + info);
}

function errorHandler(message) {
    console.error('Handler: Error in secure comm - details: ' + message);
}

function receivedHandler(received) {
    if (received.data.length > 65535) {
        console.log('Handler: data is too large to display, to store in file use saveData command');
    }
    else {
    	console.log('Handler: topic & data: ' + received.topic + ' : ' + received.data.toString());
    }
}

function subscriptionHandler(info) {
    console.log('Handler: ' + info);
}

var configFilePath = 'configs/net1/server.config';
if (process.argv.length > 2) {
    configFilePath = process.argv[2];
}
var secureSubscriber = new SecureSubscriber(configFilePath);
secureSubscriber.initialize();
secureSubscriber.setOutputHandler('connection', connectionHandler);
secureSubscriber.setOutputHandler('error', errorHandler);
secureSubscriber.setOutputHandler('received', receivedHandler);
secureSubscriber.setOutputHandler('subscription', subscriptionHandler);

function getDefaultTopic() {
	var entityInfo = secureSubscriber.getEntityInfo();
	if (entityInfo.distProtocol == 'TCP') {
		return 'Ptopic';
	}
	else if (entityInfo.distProtocol == 'UDP') {
		return 8088;
		//return '230.185.192.108:8088';
	}
	else {
		throw 'unrecognized protocol! - ' + entityInfo.distProtocol;
	}
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
            console.log(secureSubscriber.showKeys());
        }
        else if (command == 'showSocket') {
            console.log('showSocket command. current secure subscription socket: ');
            console.log(secureSubscriber.showSocket());
        }
        else if (command == 'sub') {
            console.log('subscribe command');
            var topic = getDefaultTopic();
            if (message != undefined) {
                topic = message;
            }
            secureSubscriber.provideInput('subscribe', topic);
        }
        else if (command == 'unsub') {
            console.log('unsubscribe command');
            var topic = getDefaultTopic();
            if (message != undefined) {
                topic = message;
            }
            secureSubscriber.provideInput('unsubscribe', topic);
        }
        else if (command == 'skReqSub') {
            console.log('skReqSub (Session key request for target subscribe topic) command');
            var numKeys = 3;
            if (message != undefined) {
                numKeys = parseInt(message);
            }
            sendSessionKeyRequest({subTopic: 'Ptopic'}, numKeys, {targetSessionKeyCache: 'Subscribe'});
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
        else {
            console.log('unrecognized command: ' + command);
        }
    }
    var entityInfo = secureSubscriber.getEntityInfo();
    console.log(entityInfo.name + ':' + entityInfo.group + ' prompt>');
};

process.stdin.on('readable', commandInterpreter);
