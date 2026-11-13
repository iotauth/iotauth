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
 * Example echo server entity which responds to the client every time it receives a message
 * over an authorized channel.
 *
 * @author Hokeun Kim
 */

"use strict";

const util = require('node:util');
const iotAuth = require('../accessors/node_modules/iotAuth');
const serverCommands = require('./serverCommands');

// Echoes the received data back to the client it came from.
function receivedHandler(received) {
    serverCommands.logReceived(received);
    secureCommServer.provideInput('toSend', {data: received.data, id: received.id});
}

if (process.argv.length > 3) {
    const workingDirectory = process.argv[3];
    console.log('changing working directory to: ' + workingDirectory);
    process.chdir(workingDirectory);
}

// Parameters for experiments
let connectionTimeout = 2000;
let migrationEnabled = true;
let authFailureThreshold = 3;
let migrationFailureThreshold = 3;
/////

if (process.argv.length > 4) {
    const expOptions = iotAuth.loadJSONConfig(process.argv[4]);
    console.log('Experimental options for echoServer: ' + util.inspect(expOptions));
    connectionTimeout = expOptions.connectionTimeout;
    migrationEnabled = expOptions.migrationEnabled;
    authFailureThreshold = expOptions.authFailureThreshold;
    migrationFailureThreshold = expOptions.migrationFailureThreshold;
}

const secureCommServer = serverCommands.createServer('configs/net1/server.config', receivedHandler);

// set parameters for migration
secureCommServer.setParameter('migrationEnabled', migrationEnabled);
secureCommServer.setParameter('authFailureThreshold', authFailureThreshold);
secureCommServer.setParameter('migrationFailureThreshold', migrationFailureThreshold);
// set connection timeout
secureCommServer.setEntityInfo('connectionTimeout', connectionTimeout);

serverCommands.startCommandInterpreter(secureCommServer);
