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
 * Shared behavior of the example server entities (server.js, echoServer.js,
 * gate.js, and targetItem.js): the standard output handlers, creation of the
 * SecureCommServer from the command line, and the interactive command prompt
 * that reads commands from stdin.
 *
 * Each server passes its own 'received' handler to createServer() and picks
 * the standard commands it offers at the prompt (all of them by default).
 * Entity-specific commands can be added with the extraCommands option of
 * startCommandInterpreter(); they have the same shape as the entries of
 * standardCommands below.
 *
 * @author Hokeun Kim
 */

"use strict";

const fs = require('node:fs');
const SecureCommServer = require('../accessors/SecureCommServer');

const DEFAULT_SEND_FILE = '../data_examples/data.bin';
const DEFAULT_SAVE_FILE = '../data_examples/receivedData.bin';
// Payloads above this size are not printed to the console.
const MAX_DISPLAYED_DATA_LENGTH = 65535;

// --- Standard output handlers ---

function connectionHandler(info) {
    console.log('Handler: ' + info);
}

function errorHandler(info) {
    console.error('Handler: ' + info);
}

function listeningHandler(port) {
    console.log('Handler: listening on port ' + port);
}

// Logs data received from a client. Call this from a 'received' handler.
function logReceived(received) {
    if (received.data.length > MAX_DISPLAYED_DATA_LENGTH) {
        console.log('Handler: ' + 'socketID: ' + received.id);
        console.log('data is too large to display, to store in file use saveData command');
    }
    else {
        console.log('Handler: ' + 'socketID: ' + received.id + ' data: ' + received.data.toString());
    }
}

// --- Server creation ---

// Creates and initializes a SecureCommServer with the standard output handlers
// and the given 'received' handler. The config file path is the first command
// line argument, or defaultConfigPath when no argument is given.
function createServer(defaultConfigPath, receivedHandler) {
    let configFilePath = defaultConfigPath;
    if (process.argv.length > 2) {
        configFilePath = process.argv[2];
    }

    const server = new SecureCommServer(configFilePath);
    server.initialize();
    server.setOutputHandler('connection', connectionHandler);
    server.setOutputHandler('error', errorHandler);
    server.setOutputHandler('listening', listeningHandler);
    server.setOutputHandler('received', receivedHandler);
    return server;
}

// --- Standard commands ---

// Splits a line of input into the command and the rest of the line.
function parseCommand(chunk) {
    const input = chunk.toString().trim();
    const separator = input.indexOf(' ');
    if (separator < 0) {
        return {command: input, message: undefined};
    }
    return {command: input.slice(0, separator), message: input.slice(separator + 1)};
}

// Splits "<socketID> <text>" into a socket ID and the text; null when either is missing.
function parseSocketTarget(message) {
    if (message === undefined) {
        return null;
    }
    const trimmed = message.trim();
    const separator = trimmed.indexOf(' ');
    if (separator < 0) {
        return null;
    }
    return {
        socketID: Number.parseInt(trimmed.slice(0, separator), 10),
        text: trimmed.slice(separator + 1)
    };
}

function parseCount(message, defaultCount) {
    return message === undefined ? defaultCount : Number.parseInt(message, 10);
}

// Sends a file to one client, or to all connected clients when socketID is null.
function sendFile(server, fileName, socketID) {
    console.error('======== log for experiments: publishing message =========');
    const fileData = fs.readFileSync(fileName);
    console.log('file data length: ' + fileData.length);
    server.provideInput('toSend', {data: fileData, id: socketID});
}

// The standard commands, in the order shown by 'help'. Each entry has the
// usage shown by 'help', a description, optional aliases, and run(server,
// message), where message is the rest of the input line or undefined.
const standardCommands = {
    send: {
        usage: 'send <message>',
        description: 'Send message to all connected clients',
        run(server, message) {
            console.log('send command (sending to all connected clients)');
            if (message === undefined) {
                console.log('no message!');
                return;
            }
            // id is set to null to indicate sending to all connected clients.
            server.provideInput('toSend', {data: Buffer.from(message), id: null});
        }
    },
    sendTo: {
        usage: 'sendTo <socketID> <msg>',
        description: 'Send message to a specific client by socket ID',
        run(server, message) {
            console.log('sendTo command (sending to a specific client- usage: sendTo [socketID] [message]');
            const target = parseSocketTarget(message);
            if (target === null) {
                console.log('Please specify both socket ID and message!');
                return;
            }
            server.provideInput('toSend', {data: Buffer.from(target.text), id: target.socketID});
        }
    },
    sendFile: {
        usage: 'sendFile [filepath]',
        description: 'Send a binary file to all connected clients\n(default: ' + DEFAULT_SEND_FILE + ')',
        run(server, message) {
            console.log('sendFile command');
            sendFile(server, message === undefined ? DEFAULT_SEND_FILE : message, null);
        }
    },
    sendFileTo: {
        usage: 'sendFileTo <id> [filepath]',
        description: 'Send a binary file to a specific client',
        run(server, message) {
            console.log('sendFileTo command');
            if (message === undefined) {
                console.log('socketID must be specified!');
                return;
            }
            const args = message.split(' ');
            const fileName = args.length > 1 ? args[1] : DEFAULT_SEND_FILE;
            sendFile(server, fileName, Number.parseInt(args[0], 10));
        }
    },
    skReq: {
        usage: 'skReq [numKeys]',
        description: 'Request session keys for future clients (default: 3)',
        run(server, message) {
            console.log('skReq (Session key request for cached keys that will be used by clients) command');
            server.getSessionKeysForFutureClients(parseCount(message, 3));
        }
    },
    skReqPub: {
        usage: 'skReqPub [numKeys]',
        description: 'Request session keys for publish topic (default: 1)',
        run(server, message) {
            console.log('skReqPub (Session key request for target publish topic) command');
            server.getSessionKeysForPublish(parseCount(message, 1));
        }
    },
    saveData: {
        usage: 'saveData [filepath]',
        description: 'Save last received data to a file',
        run(server, message) {
            console.log('saveData command');
            const received = server.latestOutput('received');
            if (received === undefined) {
                console.log('No data to be saved!');
                return;
            }
            const fileName = message === undefined ? DEFAULT_SAVE_FILE : message;
            fs.writeFileSync(fileName, received);
            console.log('file data saved to ' + fileName);
        }
    },
    showKeys: {
        usage: 'showKeys',
        description: 'Show current distribution key and session keys',
        run(server) {
            console.log('showKeys command. distribution key and session keys: ');
            console.log(server.showKeys());
        }
    },
    showSocket: {
        usage: 'showSocket',
        description: 'Show current secure server socket info',
        run(server) {
            console.log('showSocket command. current secure client socket: ');
            console.log(server.showSocket());
        }
    },
    mig: {
        usage: 'mig',
        description: 'Migrate to a trusted Auth',
        run(server) {
            console.log('migration request command!');
            server.migrateToTrustedAuth();
        }
    },
    finComm: {
        usage: 'finComm  (or f)',
        description: 'End all active secure communications',
        aliases: ['f'],
        run(server) {
            console.log('finComm command');
            server.provideInput('toSend', null);
        }
    }
};

// --- Command prompt ---

const HELP_COLUMN_WIDTH = 28;

function printHelp(entries) {
    console.log('Available commands:');
    for (const entry of entries) {
        const lines = entry.description.split('\n');
        console.log('  ' + entry.usage.padEnd(HELP_COLUMN_WIDTH) + lines[0]);
        for (const line of lines.slice(1)) {
            console.log('  ' + ''.padEnd(HELP_COLUMN_WIDTH) + line);
        }
    }
}

// Builds the table of available commands: 'help', the named standard
// commands, and the extra commands, keyed by name and alias.
function buildCommandTable(commandNames, extraCommands) {
    const entries = [];
    for (const name of commandNames) {
        if (!(name in standardCommands)) {
            throw new Error('Unknown standard command: ' + name);
        }
        entries.push({name, ...standardCommands[name]});
    }
    for (const name of Object.keys(extraCommands)) {
        entries.push({name, ...extraCommands[name]});
    }

    const help = {
        name: 'help',
        usage: 'help',
        description: 'Show this help message',
        run() {
            printHelp([help, ...entries]);
        }
    };

    const table = {};
    for (const entry of [help, ...entries]) {
        table[entry.name] = entry;
        for (const alias of entry.aliases || []) {
            table[alias] = entry;
        }
    }
    return table;
}

// Runs one line of input against the command table.
function executeCommandLine(table, server, line) {
    const {command, message} = parseCommand(line);
    const entry = table[command];
    if (entry === undefined) {
        console.log('unrecognized command: ' + command);
        return;
    }
    entry.run(server, message);
}

function printPrompt(server) {
    const entityInfo = server.getEntityInfo();
    console.log(entityInfo.name + ':' + entityInfo.group + ' prompt>');
}

// Returns the stdin 'readable' handler that interprets commands for the server.
// options.commands lists the standard commands to offer (default: all);
// options.extraCommands adds entity-specific commands by name.
function createCommandInterpreter(server, options) {
    const settings = options || {};
    const table = buildCommandTable(
        settings.commands || Object.keys(standardCommands),
        settings.extraCommands || {});

    return function commandInterpreter() {
        let chunk;
        printPrompt(server);
        // Use a loop to make sure we read all available data.
        while ((chunk = process.stdin.read()) !== null) {
            executeCommandLine(table, server, chunk);
            printPrompt(server);
        }
    };
}

// Starts reading commands for the server from stdin.
function startCommandInterpreter(server, options) {
    process.stdin.on('readable', createCommandInterpreter(server, options));
}

module.exports = {
    logReceived,
    createServer,
    parseCommand,
    standardCommands,
    buildCommandTable,
    executeCommandLine,
    createCommandInterpreter,
    startCommandInterpreter
};
