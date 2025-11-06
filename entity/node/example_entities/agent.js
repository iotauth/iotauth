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
 * Example agent entity written using SecureCommClient accessor.
 * @author Sunyoung Kim
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
    } else if (commandArg == 'getKey'){
        var keyId = parseInt(process.argv[4]);
        secureCommClient.getSessionKeysForGrantAccess(keyId);
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

        if (command == 'getKey') {
            console.log('getKey command. get sesssion key by ID: ');
            secureCommClient.getSessionKeysForGrantAccess(keyId);
        }

        else {
            console.log('unrecognized command: ' + command);
        }
        console.log(entityInfo.name + ':' + entityInfo.group + ' prompt>');
    }
};

process.stdin.on('readable', commandInterpreter);