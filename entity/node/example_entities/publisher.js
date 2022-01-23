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
 * Example publisher entity written using SecurePublisher accessor.
 * @author Hokeun Kim
 */
"use strict";

var fs = require('fs');
var SecurePublisher = require('../accessors/SecurePublisher');

function connectionHandler(info) {
    console.log('Handler: ' + info);
}

function errorHandler(message) {
    console.error('Handler: Error in secure comm - details: ' + message);
}

function readyHandler(info) {
    console.log('Handler: ' + info);
}

var configFilePath = 'configs/net1/client.config';
if (process.argv.length > 2) {
    configFilePath = process.argv[2];
}
var securePublisher = new SecurePublisher(configFilePath);
securePublisher.setParameter('numKeysPerRequest', 1);
securePublisher.setParameter('topic', 'Ptopic');
securePublisher.initialize();
securePublisher.setOutputHandler('connection', connectionHandler);
securePublisher.setOutputHandler('error', errorHandler);
securePublisher.setOutputHandler('ready', readyHandler);

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

        if (command == 'showKeys') {
            console.log('showKeys command. distribution key and session keys: ');
            console.log(securePublisher.showKeys());
        }
        else if (command == 'showSocket') {
            console.log('showSocket command. current secure publication socket: ');
            console.log(securePublisher.showSocket());
        }
        else if (command == 'spub') {
            console.log('spub command, secure publish');
            if (message == undefined) {
                console.log('no message!');
                return;
            }
            securePublisher.provideInput('toPublish', Buffer.from(message));
        }
        else if (command == 'spubFile') {
            console.log('spubFile command, secure publish of file');
            var fileName = '../data_examples/data.bin';
            if (message != undefined) {
                fileName = message;
            }
            var fileData = fs.readFileSync(fileName);
            console.log('file data length: ' + fileData.length);
            securePublisher.provideInput('toPublish', fileData);
        }
        else {
            console.log('unrecognized command: ' + command);
        }
    }
    var entityInfo = securePublisher.getEntityInfo();
    console.log(entityInfo.name + ':' + entityInfo.group + ' prompt>');
};

process.stdin.on('readable', commandInterpreter);
