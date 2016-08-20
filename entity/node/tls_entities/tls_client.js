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
 * Client entity using SSL/TLS.
 * @author Hokeun Kim
 */

"use strict";

var tls = require('tls');
var fs = require('fs');
var common = require('./tls_common');
var commState = common.commState;

var options = {
    // These are necessary only if using the client certificate authentication
    key: fs.readFileSync('credentials/ClientKey.pem'),
    cert: fs.readFileSync('credentials/ClientCert.pem'),
    ciphers: 'AES128-SHA256',   // TLS_RSA_WITH_AES_128_CBC_SHA256
    //ciphers: 'ECDHE-RSA-AES256-SHA256',
    //secureProtocol: 'TLSv1_2_method',
    //ciphers: 'ECDHE-RSA-AES128-SHA',

    // This is necessary only if the server uses the self-signed certificate
    ca: [ fs.readFileSync('credentials/CACert.pem') ]
};

var currentState = commState.IDLE;
var curSocket;

function initComm(serverPort) {
    curSocket = tls.connect(serverPort, options, function() {
        console.log('client connected to ' + serverPort + ' ' +
            curSocket.authorized ? 'authorized' : 'unauthorized');
        currentState = commState.IN_COMM;
    });
    curSocket.setEncoding('utf8');
    curSocket.on('data', function(data) {
        console.log('received: ' +  data);
    });
    curSocket.on('end', function() {
        console.log('disconnected from server');
    });
    curSocket.on('error' , function(error) {
        console.log(error.toString());
    });
};

function finComm() {
    curSocket.end();
    currentState = commState.IDLE;
};

function commandInterpreter() {
    console.log('TLS_Client prompt>');
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
            }
            else {
                var serverPort = common.SERVER_PORT;

                if (message != undefined) {
                    serverPort = parseInt(message);
                }
                
                console.log('initComm command, connecting to server port ' + serverPort);
                initComm(serverPort);
            }
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
        else if (command == 'send') {
            console.log('send command');
            if (currentState != commState.IN_COMM) {
                console.log('invalid send command, it is not in IN_COMM state');
                return;
            }
            if (message == undefined) {
                console.log('no message!');
                return;
            }
            curSocket.write(message);
        }
        else if (command == 'sendFile') {
            if (currentState != commState.IN_COMM) {
                console.log('invalid send command, it is not in IN_COMM state');
            }
            else {
                console.log('sendFile command');
                var fileData = fs.readFileSync('../data_examples/data.bin');
                console.log('file data length: ' + fileData.length);
                curSocket.write(fileData);
            }
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
            var serverPortBase = 21100;
            var repeater;
            var repeater2;
            var repeater2 = function() {
                finComm();
                idx++;
                if (idx < serverCount) {
                    setTimeout(repeater, 1000);
                }
            }
            var repeater = function() {
                initComm(serverPortBase + idx);
                setTimeout(repeater2, 1000);
            }
            repeater();
        }
        else {
            console.log('unrecognized command: ' + command);
        }
    }
};


process.stdin.on('readable', commandInterpreter);