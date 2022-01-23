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
 * Example client entity written using SecureCommClient accessor.
 * @author Hokeun Kim
 */
"use strict";

var fs = require('fs');
var SecureCommClient = require('../accessors/SecureCommClient');

function connectedHandler(connected) {
    if (connected == true) {
        console.log('Handler: communication initialization succeeded');
    }
    else {
        console.log('Handler: secure connection with the server closed.');
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
}

var configFilePath = 'configs/net1/client.config';
if (process.argv.length > 2) {
    configFilePath = process.argv[2];
}

var secureCommClient = new SecureCommClient(configFilePath);
secureCommClient.initialize();
secureCommClient.setOutputHandler('connected', connectedHandler);
secureCommClient.setOutputHandler('error', errorHandler);
secureCommClient.setOutputHandler('received', receivedHandler);

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

function commandInterpreter() {
    let chunk;
    const entityInfo = secureCommClient.getEntityInfo();
    console.log(entityInfo.name + ':' + entityInfo.group + ' prompt>');
    // Use a loop to make sure we read all available data.
    while ((chunk = process.stdin.read()) !== null) {
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
        console.log(entityInfo.name + ':' + entityInfo.group + ' prompt>');
    }
};

process.stdin.on('readable', commandInterpreter);