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
 * Example auto client entity which sends a message periodically and automatically.
 * This is written using SecureCommClient accessor.
 *
 * @author Hokeun Kim
 */
"use strict";

var fs = require('fs');
var util = require('util');
var iotAuth = require('../accessors/node_modules/iotAuth');
var SecureCommClient = require('../accessors/SecureCommClient');

// Parameters for experiments
var autoSendPeriod = 5000;
var useSameSessionKeyCount = 2;
////

var currentRemainingRequestCount = 0;
var currentTimeout = null;

var actualResponseCount = 0;
var expectedResponseCount = 0;

function printAvailability() {
    console.log('Resp-actual/expected/ratio/ts: ' + actualResponseCount + ' ' + expectedResponseCount + ' ' + actualResponseCount/expectedResponseCount + ' ' + new Date().getTime());
}
function increaseAcutalResponseCount() {
    actualResponseCount++;
    printAvailability();
}
function increaseExpectedResponseCount(increase) {
    if (increase == null) {
        increase = 1;
    }
    expectedResponseCount += increase;
    printAvailability();
}

function autoSend() {
    var fileName = '../data_examples/data.bin';
    var fileData = fs.readFileSync(fileName);
    console.log('file data length: ' + fileData.length);
    //secureCommClient.provideInput(fileData);
    console.log('sending at ' + new Date());    
    secureCommClient.provideInput('toSend', Buffer.from('data' + currentRemainingRequestCount));
    currentRemainingRequestCount--;
    if (currentRemainingRequestCount > 0) {
        currentTimeout = setTimeout(autoSend, autoSendPeriod);
    }
    else {
        currentTimeout = null;
    }
}

function connectedHandler(connected) {
    if (connected == true) {
        console.log('Handler: communication initialization succeeded');
        currentRemainingRequestCount = useSameSessionKeyCount;
        autoSend();
    }
    else {
        console.log('Handler: secure connection with the server closed.');
        if (currentTimeout != null) {
            clearTimeout(currentTimeout);
            currentTimeout = null;
        }
    }
}

function errorHandler(message) {
    console.error('Handler: Error in secure comm - details: ' + message);
}

function receivedHandler(data) {
    console.log('Handler: data received from server via secure communication');
    if (data.length > 65535) {
        console.log('Handler: data is too large to display, to store in file use saveData command');
    }
    else {
        console.log(data.toString());
    }
    increaseAcutalResponseCount();
}

var configFilePath = 'configs/net1/client.config';
if (process.argv.length > 2) {
    configFilePath = process.argv[2];
}

if (process.argv.length > 3) {
    var workingDirectory = process.argv[3];
    console.log('changing working directory to: ' + workingDirectory);
    process.chdir(workingDirectory);
}

// Parameters for experiments
var connectionTimeout = 2000;
var migrationEnabled = true;
var authFailureThreshold = 3;
var migrationFailureThreshold = 3;
////

if (process.argv.length > 4) {
    var expOptions = iotAuth.loadJSONConfig(process.argv[4]);
    console.log('Experimental options for autoClient: ' + util.inspect(expOptions));
    autoSendPeriod = expOptions.autoSendPeriod;
    useSameSessionKeyCount = expOptions.useSameSessionKeyCount;
    connectionTimeout = expOptions.connectionTimeout;
    migrationEnabled = expOptions.migrationEnabled;
    authFailureThreshold = expOptions.authFailureThreshold;
    migrationFailureThreshold =expOptions.migrationFailureThreshold;
}

var secureCommClient = new SecureCommClient(configFilePath);
secureCommClient.initialize();
secureCommClient.setOutputHandler('connected', connectedHandler);
secureCommClient.setOutputHandler('error', errorHandler);
secureCommClient.setOutputHandler('received', receivedHandler);

// set number of cached keys to 1
secureCommClient.setParameter('numKeysPerRequest', 1);
secureCommClient.setParameter('migrationEnabled', migrationEnabled);
secureCommClient.setParameter('authFailureThreshold', authFailureThreshold);
secureCommClient.setParameter('migrationFailureThreshold', migrationFailureThreshold);
// set connection timeout
secureCommClient.setEntityInfo('connectionTimeout', connectionTimeout);
/*
// For publish-subscribe experiments based individual secure connection using proposed approach
if (process.argv.length > 5) {
    var commandArg = process.argv[3];
    var serverPort = parseInt(process.argv[5]);
    if (commandArg == 'exp2') {
        var keyId = parseInt(process.argv[4]);
        secureCommClient.setParameter('keyId', keyId);
        secureCommClient.provideInput('serverHostPort', {host: 'localhost', port: serverPort});
    }
}
*/

/*
        {
            "name": "net1.server",
            "port": 21100,
            "host": "localhost"
        },
        {
            "name": "net2.server",
            "port": 22100,
            "host": "localhost"
        },
*/

var currentExpectedResponseCount = 0;
function expectedResponseCounter() {
    increaseExpectedResponseCount();
    currentExpectedResponseCount --;
    if (currentExpectedResponseCount > 0) {
        setTimeout(expectedResponseCounter, autoSendPeriod);
    }
}

var targetServerInfoList = secureCommClient.getTargetServerInfoList();
function autoConnect() {
    secureCommClient.provideInput('serverHostPort', {
        host: targetServerInfoList[0].host,
        port: targetServerInfoList[0].port
    });
    setTimeout(autoConnect, autoSendPeriod * useSameSessionKeyCount);
    currentExpectedResponseCount = useSameSessionKeyCount;
    expectedResponseCounter();
}
autoConnect();

/*
function repeatSending() {

    secureCommClient.provideInput('serverHostPort', {host: commServerInfo.host, port: commServerInfo.port});

    var fileName = '../data_examples/data.bin';
    var fileData = fs.readFileSync(fileName);
    console.log('file data length: ' + fileData.length);
    secureCommClient.provideInput('toSend', fileData);

    setTimeout(repeatSending, 2000);
}

repeatSending();
*/

/*
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
            var targetServerInfoList = secureCommClient.getTargetServerInfoList();
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
            secureCommClient.provideInput('serverHostPort', {host: commServerInfo.host, port: commServerInfo.port});

        }
        else if (command == 'finComm' || command == 'f') {
            console.log('finComm command');
            secureCommClient.provideInput('serverHostPort', null);
        }
        else if (command == 'showKeys') {
            console.log('showKeys command. distribution key and session keys: ');
            console.log(secureCommClient.showKeys());
        }
        else if (command == 'showSocket') {
            console.log('showSocket command. current secure client socket: ');
            console.log(secureCommClient.showSocket());
        }
        else if (command == 'send') {
            console.log('send command');
            if (message == undefined) {
                console.log('no message!');
                return;
            }
            secureCommClient.provideInput('toSend', Buffer.from(message));
        }
        else if (command == 'sendFile') {
            console.log('sendFile command');
            var fileName = '../data_examples/data.bin';
            if (message != undefined) {
                fileName = message;
            }
            var fileData = fs.readFileSync(fileName);
            console.log('file data length: ' + fileData.length);

            secureCommClient.provideInput('toSend', fileData);
        }
        else if (command == 'skReq') {
            console.log('skReq (Session key request for cached keys that will be used to connect to servers) command');
            var numKeys = 3;
            if (message != undefined) {
                numKeys = parseInt(message);
            }
            secureCommClient.getSessionKeysForCaching(numKeys);
        }
        else if (command == 'numKeys') {
            console.log('numKeys (Set number of session keys per request) command');
            var numKeys = 3;
            if (message != undefined) {
                numKeys = parseInt(message);
            }
            secureCommClient.setParameter('numKeysPerRequest', numKeys);
        }
        else if (command == 'saveData') {
            console.log('saveData command');
            var received = secureCommClient.latestOutput('received');
            if (received == undefined) {
                console.log('No data to be saved!');
                return;
            }
            var fileName = '../data_examples/receivedData.bin';
            if (message != undefined) {
                fileName = message;
            }
            fs.writeFileSync(fileName, received);
            console.log('file data saved to ' + fileName);
        }
        else if (command == 'mig') {
            console.log('migration request command!');
            secureCommClient.migrateToTrustedAuth();

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
            console.log('start experiments for ' + serverCount + ' servers ...');
            var idx = 0;
            var repeater;
            var repeater2;
            var repeater2 = function() {
                secureCommClient.provideInput('serverHostPort', null);
                //commServerInfo.port++;
                if (idx < serverCount) {
                    setTimeout(repeater, 500);
                }
            }
            var repeater = function() {
                idx++;
                console.log('round ' + idx);
                secureCommClient.provideInput('serverHostPort', {host: 'localhost', port: serverPort});
                setTimeout(repeater2, 500);
            }
            repeater();
        }
        else {
            console.log('unrecognized command: ' + command);
        }
    }
    var entityInfo = secureCommClient.getEntityInfo();
    console.log(entityInfo.name + ':' + entityInfo.group + ' prompt>');
};

process.stdin.on('readable', commandInterpreter);
*/
