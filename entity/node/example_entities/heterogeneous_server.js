"use strict";

var SecureCommServer = require('../accessors/SecureCommServer');

var configFilePath = 'configs/heterogeneous/nodeServer.config';
if (process.argv.length > 2) {
    configFilePath = process.argv[2];
}

console.log('[SST] Starting heterogeneous Node.js server with config: ' + configFilePath);

var secureCommServer = new SecureCommServer(configFilePath);
secureCommServer.initialize();

secureCommServer.setOutputHandler('listening', function(port) {
    console.log('[SST] Node.js server listening on port ' + port);
});

secureCommServer.setOutputHandler('connection', function(info) {
    console.log('[SST] Secure connection event: ' + info);
});

secureCommServer.setOutputHandler('received', function(received) {
    var message = received.data.toString('utf8');
    console.log('[SST] Received from C client #' + received.id + ': ' + message);

    secureCommServer.provideInput('toSend', {
        id: received.id,
        data: Buffer.from('ACK from heterogeneous Node.js server: ' + message)
    });
});

secureCommServer.setOutputHandler('error', function(info) {
    console.error('[SST ERROR] ' + info);
});
