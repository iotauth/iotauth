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
 * Generator for entity configuration files.
 * @author Hokeun Kim
 */

"use strict";

var fs = require('fs');

var strConfig = fs.readFileSync('template.config', 'utf8');
var jsonConfig = JSON.parse(strConfig);

console.log(jsonConfig);

function getAuthInfo(id, protocol) {
    var authInfo = {};
    authInfo.id = id;
    authInfo.host = 'localhost';
    if (id == 101) {
        authInfo.port = 21900;
    }
    else if (id == 102) {
        authInfo.port = 22900;
    }
    if (protocol == 'UDP') {
        authInfo.port += 2; 
    }
    authInfo.publicKey = '../../auth_certs/Auth' + id + 'EntityCert.pem';
    return authInfo;
}
/*
var tcpServerInfoList = [
    { name: 'net1.server', host: 'localhost', port: 21100 },
    { name: 'net1.ptServer', host: 'localhost', port: 21200 },
    { name: 'net1.rcServer', host: 'localhost', port: 21300 },
    { name: 'net2.server', host: 'localhost', port: 22100 },
    { name: 'net2.ptServer', host: 'localhost', port: 22200 },
    { name: 'net2.rcServer', host: 'localhost', port: 22300 }];

var udpServerInfoList = [
    { name: 'net1.udpServer', host: 'localhost', port: 21400},
    { name: 'net2.udpServer', host: 'localhost', port: 22400},
    { name: 'net1.rcUdpServer', host: 'localhost', port: 21600},
    { name: 'net2.rcUdpServer', host: 'localhost', port: 22600}];

var safetyCriticalServerInfoList = [
    { name: 'net1.safetyCriticalServer', host: 'localhost', port: 21500},
    { name: 'net2.safetyCriticalServer', host: 'localhost', port: 22500}];
*/

var cryptoInfo = {
    publicKeyCryptoSpec: { sign: 'RSA-SHA256' },
    distCryptoSpec: { cipher: 'AES-128-CBC', mac: 'SHA256' },
    sessionCryptoSpec: { cipher: 'AES-128-CBC', mac: 'SHA256' }
};

var serverList = [
    { name: 'server', port: 100 },
    { name: 'ptServer', port: 200 },
    { name: 'rcServer', port: 300 },
    { name: 'udpServer', port: 400 },
    { name: 'safetyCriticalServer', port: 500 },
    { name: 'rcUdpServer', port: 600 }];

var clientList = [
    { name: 'client' },
//    { name: 'ptClient', port: 200 },
    { name: 'rcClient' },
    { name: 'udpClient' },
    { name: 'safetyCriticalClient' },
    { name: 'rcUdpClient' }];
];
 
console.log(getAuthInfo(102, 'TCP'));

// if str.toLowerCase().includes('pt')
// just add to the server info, don't generate the file

// if str.toLowerCase().includes('udp')
// if str.toLowerCase().includes('rc')
// if str.toLowerCase().includes('safetycritical')

var tcpServerInfoList = [];
var udpServerInfoList = [];
var safetyCriticalServerInfoList = [];


    for (var i = 0; i < fileLines.length; i++) {
        var line = fileLines[i].trim();
        if (line.startsWith('//') || line.length == 0) {
            continue;
        }
        fileString += line;
    }

