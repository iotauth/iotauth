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
 * Example targetItem resource server. When an authorized client sends
 * RETRIEVE_ITEM, it replies 'retrieved'.
 * @author Sunyoung Kim
 */

"use strict";

const serverCommands = require('./serverCommands');

// Standard commands offered at the prompt; the target item does not send files.
const TARGET_ITEM_COMMANDS = ['send', 'sendTo', 'skReq', 'showKeys', 'showSocket', 'mig', 'finComm'];

function receivedHandler(received) {
    if (received.data.equals(Buffer.from('RETRIEVE_ITEM'))) {
        secureCommServer.provideInput('toSend', {data: Buffer.from('retrieved'), id: received.id});
    }
    serverCommands.logReceived(received);
}

const secureCommServer = serverCommands.createServer('configs/net1/targetItem.config', receivedHandler);
serverCommands.startCommandInterpreter(secureCommServer, {commands: TARGET_ITEM_COMMANDS});
