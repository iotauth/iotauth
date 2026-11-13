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

"use strict";

// Shared command behavior for the interactive client and delegation user.
exports.parseCommand = function(chunk) {
    const input = chunk.toString().trim();
    const separator = input.indexOf(' ');
    return separator < 0
        ? {command: input, message: undefined}
        : {command: input.slice(0, separator), message: input.slice(separator + 1)};
};

exports.selectServer = function(client, message) {
    const servers = client.getTargetServerInfoList();
    if (message === undefined) return servers[0];

    const tokens = message.split(' ');
    let server = null;
    for (const candidate of servers) {
        if (candidate.name === tokens[0]) server = candidate;
    }
    if (server === null) {
        console.log('cannot find communication server named ' + tokens[0]);
        return null;
    }
    if (tokens.length > 1) {
        const port = Number.parseInt(tokens[1]);
        console.log('serverPort is explicitly specified: ' + port);
        server.port = port;
    }
    return server;
};

exports.initComm = function(client, server) {
    const resourceName = server.group ||
        server.name.split('.')[1].replace(/^./, c => c.toUpperCase());
    console.log('initComm command targeted to ' + server.name + ' (group: ' + resourceName + ')');
    client.provideInput('serverHostPort', {host: server.host, port: server.port}, resourceName);
};

exports.finComm = function(client) {
    console.log('finComm command');
    client.provideInput('serverHostPort', null);
};
