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
 * Subscriber entity using SSL/TLS.
 * @author Hokeun Kim
 */

"use strict";

var tls = require('tls');
var fs = require('fs');
var common = require('./tls_common');

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

function subscribe(publisherPort) {
    var curSocket = tls.connect(publisherPort, options, function() {
        console.log('connected to publisher',
            curSocket.authorized ? 'authorized' : 'unauthorized');
    });
    curSocket.setEncoding('utf8');
    curSocket.on('data', function(data) {
        console.log('received: ' +  data);
    });
    curSocket.on('end', function() {
        console.log('disconnected from publisher');
    });
};

function commandInterpreter() {
    console.log('TLS_Subscriber prompt>');
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

        if (command == 'sub') {
            var publisherPort = common.PUBLISHER_PORT;

            if (message != undefined) {
                publisherPort = parseInt(message);
            }
                
            console.log('sub (subscribe) command');
            subscribe(publisherPort);
        }
        else {
            console.log('unrecognized command: ' + command);
        }
    }
};

process.stdin.on('readable', commandInterpreter);