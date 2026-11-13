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
 * Example gate resource server. When an authorized client sends OPEN_GATE, it
 * opens the gate in the Gazebo simulation and replies 'open', or 'error' when
 * the Gazebo command fails.
 * @author Sunyoung Kim
 */

"use strict";

const {execFile} = require('node:child_process');
const serverCommands = require('./serverCommands');

// Gazebo's command line tool. The absolute path avoids a PATH lookup; set
// GZ_COMMAND when gz is installed elsewhere.
const GZ_COMMAND = process.env.GZ_COMMAND || '/usr/bin/gz';
const GZ_OPEN_GATE_ARGS = [
    'topic', '-t', '/secure_door/cmd_pos',
    '-m', 'gz.msgs.Double', '-p', 'data: 1.57'
];
const GZ_TIMEOUT_MS = 10000;

// Standard commands offered at the prompt; the gate does not send files.
const GATE_COMMANDS = ['send', 'sendTo', 'skReq', 'showKeys', 'showSocket', 'mig', 'finComm'];

function reply(socketID, text) {
    secureCommServer.provideInput('toSend', {data: Buffer.from(text), id: socketID});
}

function openGate(socketID) {
    execFile(GZ_COMMAND, GZ_OPEN_GATE_ARGS, {timeout: GZ_TIMEOUT_MS}, function(error) {
        if (error) {
            console.error('Handler: Gazebo OPEN_GATE failed: ' + error.message);
            reply(socketID, 'error');
            return;
        }
        // This acknowledges command publication; actual angle is on /secure_door/state.
        console.log('Handler: Gazebo open command published (target: 1.57 rad).');
        reply(socketID, 'open');
    });
}

function receivedHandler(received) {
    if (received.data.equals(Buffer.from('OPEN_GATE'))) {
        openGate(received.id);
    }
    serverCommands.logReceived(received);
}

const secureCommServer = serverCommands.createServer('configs/net1/gate.config', receivedHandler);
serverCommands.startCommandInterpreter(secureCommServer, {commands: GATE_COMMANDS});
