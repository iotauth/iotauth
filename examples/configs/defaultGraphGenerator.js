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
 * Generator for default Auth entity graph
 * @author Hokeun Kim
 */

"use strict";

var fs = require('fs');
var JSON2 = require('JSON2');

function cloneJson(a) {
    return JSON.parse(JSON.stringify(a));
}
function capitalizeFirstLetter(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}

function getNetPortBase(netId) {
    return 20000 + netId * 1000;
}
function getAuthPortBase(netId) {
    return getNetPortBase(netId) + 900;
}
function getAuthId(netId) {
    return 100 + netId;
}
function getNetId(authId) {
    return authId - 100;
}

function populateDefaultEntityList(filesharingEnabled) {
    var DEFAULT_ENTITY_LIST = [
        { group: 'Clients',		name: 'client' },
        { group: 'Clients',		name: 'rcClient' },
        { group: 'Clients',		name: 'udpClient' },
        { group: 'Clients',	 	name: 'rcUdpClient' },
        { group: 'Clients',	 	name: 'safetyCriticalClient' },

        { group: 'Servers',		name: 'server', port: 100 },
        { group: 'Servers',		name: 'rcServer', port: 300 },
        { group: 'Servers',		name: 'udpServer', port: 400 },
        { group: 'Servers',		name: 'safetyCriticalServer', port: 500 },
        { group: 'Servers',		name: 'rcUdpServer', port: 600 },

        { group: 'PtClients',	name: 'ptClient' },
        { group: 'PtServers',	name: 'ptServer', port: 200 },
        { group: 'PtPublishers',name: 'ptPublisher' },
        { group: 'PtSubscribers',name: 'ptSubscriber' }
    ];
    var FILESHARING_ENTITY_LIST = [
        { group: 'TeamA', 		name: 'uploader'},
        { group: 'TeamB', 		name: 'downloader',         reader_type: 'entity',		owner: 'TeamA'},
        { group: 'TeamC', 		name: 'Alice',              reader_type: 'entity',		owner: 'TeamB'},
        { group: 'TeamB', 		name: 'Bob',				reader_type: 'entity',      owner: 'TeamA'},
        { group: 'TeamE', 		name: 'TeamE',				reader_type: 'group',      owner: 'TeamA'},
        { group: 'FileManager', name: 'FileSystemManager'}

    ];
    var ENTITY_LIST = [

    ];
    if (filesharingEnabled == true){
        ENTITY_LIST = FILESHARING_ENTITY_LIST;
    }
    else {
        ENTITY_LIST = DEFAULT_ENTITY_LIST;
    }
    for (var i = 0; i < ENTITY_LIST.length; i++) {
        var entity = ENTITY_LIST[i];
        entity.distProtocol = entity.name.toLowerCase().includes('udp') ? 'UDP' : 'TCP';
        entity.usePermanentDistKey = entity.name.toLowerCase().includes('rc') ? true : false;
        if (entity.name.toLowerCase().includes('pt')) {
            entity.inDerFormat = true;
            entity.distKeyValidityPeriod = '3*sec';
        }
        else if (entity.usePermanentDistKey == true) {
            entity.distKeyValidityPeriod = '365*day';
        }
        else {
            entity.distKeyValidityPeriod = '1*hour';
        }
        if (entity.group.toLowerCase().includes('servers')) {
            entity.maxSessionKeysPerRequest = 1;
        }
        else if (entity.usePermanentDistKey == true) {
            entity.maxSessionKeysPerRequest = 30;
        }
        else {
            entity.maxSessionKeysPerRequest = 5;
        }
        if (entity.name.toLowerCase().includes('safetycritical')) {
            // generates 384-bit (48-byte) secret, 128 bit for cipher, 256 bit for MAC
            const DEFAULT_DH = 'secp384r1';
            entity.diffieHellman = DEFAULT_DH;
        }
    }
    return ENTITY_LIST;
}

function generateGraph(defaultEntityList, numAuths, dbProtectionMethod, backupEnabled, backupToAll, contextualCallbackEnabled, filesharingEnabled) {
    var authList = [];
    var entityList = [];
    var authTrusts = [];
    var assignments = {};
    var filesharingLists = [];
    /*
        dbProtectionMethod: values
        DEBUG(0),
        ENCRYPT_CREDENTIALS(1),
        ENCRYPT_ENTIRE_DB(2);
    */
    const AUTH_UDP_PORT_OFFSET = 2;
    const TRUSTED_AUTH_PORT_OFFSET = 1;
    const CONTEXTUAL_CALLBACK_PORT_OFFSET = 3;
    for (var netId = 1; netId <= numAuths; netId++) {
        var authId = getAuthId(netId);
        var authInfo = {
            id: authId,
            entityHost: 'localhost',
            authHost: 'localhost',
            tcpPort: getAuthPortBase(netId),
            udpPort: getAuthPortBase(netId) + AUTH_UDP_PORT_OFFSET,
            authPort: getAuthPortBase(netId) + TRUSTED_AUTH_PORT_OFFSET,
            callbackPort: getAuthPortBase(netId) + CONTEXTUAL_CALLBACK_PORT_OFFSET,
            dbProtectionMethod: dbProtectionMethod,
            backupEnabled: backupEnabled,
            contextualCallbackEnabled: contextualCallbackEnabled
        };
        authList.push(authInfo);
        for (var otherNetId = netId + 1; otherNetId <= numAuths; otherNetId++) {
            var otherAuthId = getAuthId(otherNetId);
            var authTrust = {
                id1: authId,
                id2: otherAuthId
            };
            authTrusts.push(authTrust)
        }
        var netEntityList = cloneJson(defaultEntityList);
        for (var i = 0; i < netEntityList.length; i++) {
            var entity = netEntityList[i];
            entity.netName = 'net' + netId;
            entity.credentialPrefix = 'Net' + netId + '.' + capitalizeFirstLetter(entity.name);
            entity.name = 'net' + netId + '.' + entity.name;
            if (entity.port != null) {
                entity.port = getNetPortBase(netId) + entity.port;
                entity.host = 'localhost';
            }
            var backupToAuthList = [];
            if (backupToAll) {
                var k = netId;
                for (var j = 1; j <= numAuths; j++,k++) {
                    if (k != netId) {
                        // to make sure next AuthID shows up first and circulates
                        backupToAuthList.push(getAuthId((k-1) % numAuths) + 1);
                    }
                }
            }
            else {
                backupToAuthList.push(getAuthId((netId % numAuths) + 1));
            }
            entity.backupToAuthIds = backupToAuthList;
            assignments[entity.name] = authId;
            if(entity.owner != null & filesharingEnabled == true) {
                var fileSharingList = {
                        group: entity.group,
                        reader: entity.name,
                        readerType: entity.reader_type,
                        owner: entity.owner
                };
                filesharingLists.push(fileSharingList);
            }
            if (entity.reader_type == "group"){
                continue;
            }
            entityList.push(entity);
        }
    }

    var graph = {
        authList: authList,
        authTrusts: authTrusts,
        assignments: assignments,
        entityList: entityList,
        filesharingLists: filesharingLists
    };
    return graph;
}

var program = require('commander');
program
  .version('0.1.0')
  .option('-n, --num-auths <n>', 'Nmber of Auths', parseInt)
  .option('-o, --out-file [value]', 'Output file name')
  .option('-b, --enable-backup', 'Enable backup (boolean), defaults to false')
  .option('-a, --backup-to-all', 'Backup to all Auths (boolean), defaults to false')
  .option('-c, --enable-contextual-callback', 'Enable contextual callback (boolean), defaults to false')
  .option('-f, --filesharing-enabled', 'Enable filesharing (boolean), defaults to false')
  .parse(process.argv);

/*
    dbProtectionMethod: values
    DEBUG(0),
    ENCRYPT_CREDENTIALS(1),
    ENCRYPT_ENTIRE_DB(2);
*/
var numAuths = 2;
var dbProtectionMethod = 1;
var outputFile = 'default.graph';
var backupEnabled = false;
var backupToAll = false;
var contextualCallbackEnabled = false;
var filesharingEnabled = false;
if (program.opts().numAuths != null) {
    numAuths = program.opts().numAuths;
}
if (program.opts().outFile != null) {
    outputFile = program.opts().outFile;
}
if (program.opts().enableBackup != null) {
    backupEnabled = program.opts().enableBackup;
}
if (program.opts().backupToAll != null) {
    backupToAll = program.opts().backupToAll;
}
if (program.opts().enableContextualCallback != null) {
    contextualCallbackEnabled = program.opts().enableContextualCallback;
}
if (program.opts().filesharingEnabled != null) {
    filesharingEnabled = program.opts().filesharingEnabled;
}

console.log('Number of Auths: ' + numAuths);
console.log('Output file name: ' + outputFile);
console.log('Backup enabled?: ' + backupEnabled);
console.log('Backup to all Auths?: ' + backupToAll);
console.log('Contextual callback enabled?: ' + contextualCallbackEnabled);
console.log('Filesharing enabled?: ' + filesharingEnabled);

var defaultEntityList = populateDefaultEntityList(filesharingEnabled);
var graph = generateGraph(defaultEntityList, numAuths, dbProtectionMethod, backupEnabled, backupToAll, contextualCallbackEnabled, filesharingEnabled);

fs.writeFileSync(outputFile, 
    JSON2.stringify(graph, null, '\t'),
    'utf8'
);
