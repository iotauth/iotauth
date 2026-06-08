"use strict";

// 1. Import the SST Node.js API module
var SecureCommServer = require('../accessors/SecureCommServer');

// Point to the config file you generated earlier
var configFilePath = './net1/nodeServer.config'; 

console.log("Starting custom Node.js SST server...");

// 2. Initialize the SST Context
var secureCommServer = new SecureCommServer(configFilePath);
secureCommServer.initialize();

// 3. Define the Event Handlers
secureCommServer.setOutputHandler('listening', function(port) {
    console.log('[SST] Secure Node.js server actively listening on port ' + port);
});

secureCommServer.setOutputHandler('connection', function(info) {
    console.log('[SST] New secure connection established: ' + info);
});

secureCommServer.setOutputHandler('error', function(errorInfo) {
    console.error('[SST ERROR] ' + errorInfo);
});

// 4. Handle incoming encrypted telemetry from your C Client
secureCommServer.setOutputHandler('received', function(received) {
    // The SST API handles the decryption natively before triggering this handler
    var decryptedString = received.data.toString('utf8');
    
    console.log('\n--- Secure Payload Received ---');
    console.log('Client Socket ID: ' + received.id);
    console.log('Decrypted Data:   ' + decryptedString);
    console.log('-------------------------------\n');
    
    // Optional: Send a secure acknowledgment back to the C client
    var ackMessage = "Telemetry received safely.";
    secureCommServer.provideInput('toSend', {
        data: Buffer.from(ackMessage), 
        id: received.id 
    });
});