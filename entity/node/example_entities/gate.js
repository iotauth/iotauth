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
 * Example gate resource server.
 * @author Sunyoung Kim
 */

"use strict";

var execFile = require('child_process').execFile;
var SecureCommServer = require('../accessors/SecureCommServer');

function connectionHandler(info) {
    console.log('Handler: ' + info);
}

function errorHandler(info) {
    console.error('Handler: ' + info);
}

function listeningHandler(port) {
    console.log('Handler: listening on port ' + port);
}

function receivedHandler(received) {
    if (received.data.equals(Buffer.from('OPEN_GATE'))) {
        execFile('gz', [
            'topic', '-t', '/secure_door/cmd_pos',
            '-m', 'gz.msgs.Double', '-p', 'data: 1.57'
        ], {timeout: 10000}, function(error) {
            if (error) {
                errorHandler('Gazebo OPEN_GATE failed: ' + error.message);
                secureCommServer.provideInput('toSend', {
                    data: Buffer.from('error'), id: received.id
                });
                return;
            }
            // This acknowledges command publication; actual angle is on /secure_door/state.
            console.log('Handler: Gazebo open command published (target: 1.57 rad).');
            secureCommServer.provideInput('toSend', {
                data: Buffer.from('open'), id: received.id
            });
        });
    }
    if (received.data.length > 65535) {
        console.log('Handler: ' + 'socketID: ' + received.id);
        console.log('data is too large to display');
    }
    else {
        console.log('Handler: ' + 'socketID: ' + received.id + ' data: ' + received.data.toString());
    }
}

// to be loaded from config file
var entityInfo;
var authInfo;
var listeningServerInfo;
var cryptoInfo;

var configFilePath = 'configs/net1/gate.config';
if (process.argv.length > 2) {
    configFilePath = process.argv[2];
}

var secureCommServer = new SecureCommServer(configFilePath);
secureCommServer.initialize();
secureCommServer.setOutputHandler('connection', connectionHandler);
secureCommServer.setOutputHandler('error', errorHandler);
secureCommServer.setOutputHandler('listening', listeningHandler);
secureCommServer.setOutputHandler('received', receivedHandler);

function commandInterpreter() {
    let chunk;
    const entityInfo = secureCommServer.getEntityInfo();
    console.log(entityInfo.name + ':' + entityInfo.group + ' prompt>');
    // Use a loop to make sure we read all available data.
    while ((chunk = process.stdin.read()) !== null) {
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

        if (command == 'help') {
            console.log('Available commands:');
            console.log('  help                        Show this help message');
            console.log('  send <message>              Send message to all connected clients');
            console.log('  sendTo <socketID> <msg>     Send message to a specific client by socket ID');
            console.log('  skReq [numKeys]             Request session keys for future clients (default: 3)');
            console.log('  showKeys                    Show current distribution key and session keys');
            console.log('  showSocket                  Show current secure server socket info');
            console.log('  mig                         Migrate to a trusted Auth');
            console.log('  finComm  (or f)             End all active secure communications');
        }
        else if (command == 'showKeys') {
            console.log('showKeys command. distribution key and session keys: ');
            console.log(secureCommServer.showKeys());
        }
        else if (command == 'showSocket') {
            console.log('showSocket command. current secure client socket: ');
            console.log(secureCommServer.showSocket());
        }
        else if (command == 'skReq') {
            console.log('skReq (Session key request for cached keys that will be used by clients) command');
            var numKeys = 3;
            if (message != undefined) {
                numKeys = parseInt(message);
            }
            secureCommServer.getSessionKeysForFutureClients(numKeys);
        }
        else if (command == 'send') {
            console.log('send command (sending to all connected clients)');
            if (message == undefined) {
                console.log('no message!');
                return;
            }
            // id is set to null to indicate sending to all connected clients.
            secureCommServer.provideInput('toSend', {data: Buffer.from(message), id: null});
        }
        else if (command == 'sendTo') {
            console.log('sendTo command (sending to a specific client- usage: sendTo [socketID] [message]');
            if (message == undefined) {
                console.log('no specify both socket ID and message!');
                return;
            }
            message = message.trim();
            idx = message.indexOf(' ');
            if (idx < 0) {
                console.log('Please specify both socket ID and message!');
                return;
            }
            var socketID = parseInt(message.slice(0, idx));
            message = message.slice(idx + 1);
            secureCommServer.provideInput('toSend', {data: Buffer.from(message), id: socketID});
        }
        else if (command == 'mig') {
            console.log('migration request command!');
            secureCommServer.migrateToTrustedAuth();

        }
        else if (command == 'finComm' || command == 'f') {
            console.log('finComm command');
            secureCommServer.provideInput('toSend', null);
        }
        else {
            console.log('unrecognized command: ' + command);
        }
        console.log(entityInfo.name + ':' + entityInfo.group + ' prompt>');
    }
};

process.stdin.on('readable', commandInterpreter);

