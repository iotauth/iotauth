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
 * Generator configuration files for Auth and entity
 * @author Hokeun Kim
 */

"use strict";

var fs = require('fs');
var JSON2 = require('JSON2');
var common = require('./common');
const execFileSync = require('child_process').execFileSync;

// get graph file
if (process.argv.length <= 2) {
    console.error('Graph file must be provided!');
    process.exit(1);
}
var graphFile = process.argv[2];
var graph = JSON.parse(fs.readFileSync(graphFile));

// basic directories
const EXAMPLES_DIR = process.cwd() + '/';
process.chdir('..');
const PROJ_ROOT_DIR = process.cwd() + '/';
const AUTH_DATABASES_DIR = PROJ_ROOT_DIR + 'auth/databases/';
const AUTH_PROPERTIES_DIR = PROJ_ROOT_DIR + 'auth/properties/';

function getAuthConfigDir(authId) {
    return AUTH_DATABASES_DIR + 'auth' + authId + '/configs/';
}
var authList = graph.authList;
function createConfigDirs() {
    for (var i = 0; i < authList.length; i++) {
        var auth = authList[i];
        execFileSync('mkdir', ['-p', getAuthConfigDir(auth.id)]);
    }
}

// generate registered entity tables
function getRegisteredEntity(entity) {
    var registeredEntity = {
        Name: entity.name,
        Group: entity.group,
        DistProtocol: entity.distProtocol,
        UsePermanentDistKey: entity.usePermanentDistKey,
        MaxSessionKeysPerRequest: entity.maxSessionKeysPerRequest,
        DistKeyValidityPeriod: entity.distKeyValidityPeriod,
        DistCryptoSpec: entity.distributionCryptoSpec.cipher + ':' + entity.distributionCryptoSpec.mac,
        Active: true,
        BackupToAuthIDs: entity.backupToAuthIds,
        BackupFromAuthID: -1
    }

    if (entity.usePermanentDistKey == true) {
        registeredEntity.DistCipherKeyFilePath = 'entity_keys/'+ entity.credentialPrefix + 'CipherKey.key';
        registeredEntity.DistMacKeyFilePath = 'entity_keys/' + entity.credentialPrefix + 'MacKey.key';
    }
    else {
        registeredEntity.PublicKeyCryptoSpec = common.DEFAULT_SIGN;
        if (entity.diffieHellman != null) {
            registeredEntity.PublicKeyCryptoSpec += (':DH-' + entity.diffieHellman);
        }
        registeredEntity.PublicKeyFile = 'entity_certs/' + entity.credentialPrefix + 'Cert.pem';
    }
    return registeredEntity;
}
function generateRegisteredEntityTables() {
    var registeredEntityTables = {};
    for (var i = 0; i < authList.length; i++) {
        var auth = authList[i];
        registeredEntityTables[auth.id] = [];
    }
    var assignments = graph.assignments;
    var entityList = graph.entityList;
    for (var i = 0; i < entityList.length; i++) {
        var entity = entityList[i];
        registeredEntityTables[assignments[entity.name]].push(getRegisteredEntity(entity));
    }
    for (var i = 0; i < authList.length; i++) {
        var auth = authList[i];
        var configFilePath = getAuthConfigDir(auth.id) + 'Auth' + auth.id + 'RegisteredEntityTable.config';
        console.log('Writing Auth config to ' + configFilePath + ' ...');
        fs.writeFileSync(configFilePath, JSON2.stringify(registeredEntityTables[auth.id], null, '\t'), 'utf8');
    }
}

// generate filesharing info table
function getFilesharingInfo(entity) {
    if (entity.readerType == "group") {
        entity.reader = entity.group;
    }
    var filesharingInfo = {
        Reader: entity.reader,
        ReaderType: entity.readerType,
        Owner: entity.owner
    }
    return filesharingInfo;
}
function generateFileSharingInfoTables() {
    var filesharingInfoTables = {};
    for (var i = 0; i < authList.length; i++) {
        var auth = authList[i];
        filesharingInfoTables[auth.id] = [];
    }
    var assignments = graph.assignments;
    var entityList = graph.filesharingLists;
    for (var i = 0; i < entityList.length; i++) {
        var entity = entityList[i];
        filesharingInfoTables[assignments[entity.reader]].push(getFilesharingInfo(entity));
    }
    for (var i = 0; i < authList.length; i++) {
        var auth = authList[i];
        var configFilePath = getAuthConfigDir(auth.id) + 'Auth' + auth.id + 'FileSharingInfoTable.config';
        console.log('Writing Auth config to ' + configFilePath + ' ...');
        fs.writeFileSync(configFilePath, JSON2.stringify(filesharingInfoTables[auth.id], null, '\t'), 'utf8');
    }
}

// generate client policy tables
function addServerClientPolicy(list, requestingGroup, target, absoluteValidity, relativeValidity) {
    list.push({
        RequestingGroup: requestingGroup,
        TargetType: 'Group',
        Target: target,
        MaxNumSessionKeyOwners: 2,
        SessionCryptoSpec: common.DEFAULT_CIPHER + ':' + common.DEFAULT_MAC,
        AbsoluteValidity: absoluteValidity,
        RelativeValidity: relativeValidity
    });
}
function addPubSubPolicy(list, requestingGroup, isPub) {
    list.push({
        RequestingGroup: requestingGroup,
        TargetType: isPub ? 'PubTopic' : 'SubTopic',
        Target: 'Ptopic',
        MaxNumSessionKeyOwners: 64,
        SessionCryptoSpec: common.DEFAULT_CIPHER + ':' + common.DEFAULT_MAC,
        AbsoluteValidity: '6*hour',
        RelativeValidity: '3*hour'
    });
}
// Add policy for upload and download files
function addUploadDownloadlPolicy(list, requestingGroup, target) {
    list.push({
        RequestingGroup: requestingGroup,
        TargetType: 'FileSharing',
        Target: target,
        MaxNumSessionKeyOwners: 10,
        SessionCryptoSpec: common.DEFAULT_CIPHER + ':' + common.DEFAULT_MAC,
        AbsoluteValidity: '365*day',
        RelativeValidity: '365*day'
    });    
}
// generate client policy tables
function addComputeCompactionPolicy(list, requestingGroup, target, absoluteValidity, relativeValidity) {
    list.push({
        RequestingGroup: requestingGroup,
        TargetType: 'Group',
        Target: target,
        MaxNumSessionKeyOwners: 2,
        SessionCryptoSpec: 'AES-128-CTR:SHA256',
        AbsoluteValidity: absoluteValidity,
        RelativeValidity: relativeValidity
    });
    list.push({
        RequestingGroup: target,
        TargetType: 'Group',
        Target: requestingGroup,
        MaxNumSessionKeyOwners: 2,
        SessionCryptoSpec: 'AES-128-CTR:SHA256',
        AbsoluteValidity: absoluteValidity,
        RelativeValidity: relativeValidity
    });
}

function generateCommunicationPolicyTables() {
    var policyList = [];
    addServerClientPolicy(policyList, 'Clients', 'Servers', '1*day', '2*hour');
    addServerClientPolicy(policyList, 'PtClients', 'Servers', '1*day', '2*hour');
    addServerClientPolicy(policyList, 'Clients', 'PtServers', '1*hour', '20*sec');
    addServerClientPolicy(policyList, 'PtClients', 'PtServers', '2*hour', '20*sec');
    addPubSubPolicy(policyList, 'Clients', true);
    addPubSubPolicy(policyList, 'Servers', true);
    addPubSubPolicy(policyList, 'Clients', false);
    addPubSubPolicy(policyList, 'Servers', false);
    addPubSubPolicy(policyList, 'PtPublishers', true);
    addPubSubPolicy(policyList, 'PtSubscribers', false);
    addUploadDownloadlPolicy(policyList,'TeamA','TeamB');
    addUploadDownloadlPolicy(policyList,'TeamB','TeamC');
    addUploadDownloadlPolicy(policyList,'TeamC','TeamE');
    addServerClientPolicy(policyList, 'TeamA', 'Servers', '1*day', '2*hour');
    addServerClientPolicy(policyList, 'TeamA', 'FileManager', '1*day', '2*hour');
    addServerClientPolicy(policyList, 'TeamB', 'FileManager', '1*day', '2*hour');
    addServerClientPolicy(policyList, 'TeamC', 'FileManager', '1*day', '2*hour');
    addComputeCompactionPolicy(policyList, 'ComputeNodes', 'CompactionNodes', '1*day', '2*hour');
    for (var i = 0; i < authList.length; i++) {
        var auth = authList[i];
        var configFilePath = getAuthConfigDir(auth.id) + 'Auth' + auth.id + 'CommunicationPolicyTable.config';
        console.log('Writing Auth config to ' + configFilePath + ' ...');
        fs.writeFileSync(configFilePath, JSON2.stringify(policyList, null, '\t'), 'utf8');
    }
}

// generate trusted Auth tables
function getTrustedAuth(auth) {
    return {
        ID: auth.id, Host: auth.authHost, EntityHost: auth.entityHost, Port: auth.authPort,
        InternetCertificatePath: 'trusted_auth_certs/Auth' + auth.id + 'InternetCert.pem',
        EntityCertificatePath: 'trusted_auth_certs/Auth' + auth.id + 'EntityCert.pem',
        HeartbeatPeriod: -1,
        FailureThreshold: -1
    }
}
function generateTrustedAuthTables() {
    var trustedAuthTables = {};
    var auths = {};
    var authTrusts = graph.authTrusts;
    for (var i = 0; i < authList.length; i++) {
        var auth = authList[i];
        trustedAuthTables[auth.id] = [];
        auths[auth.id] = auth;
    }
    for (var i = 0; i < authTrusts.length; i++) {
        var authTrust = authTrusts[i];
        trustedAuthTables[authTrust.id1].push(getTrustedAuth(auths[authTrust.id2]));
        trustedAuthTables[authTrust.id2].push(getTrustedAuth(auths[authTrust.id1]));
    }
    for (var i = 0; i < authList.length; i++) {
        var auth = authList[i];
        var configFilePath = getAuthConfigDir(auth.id) + 'Auth' + auth.id + 'TrustedAuthTable.config';
        console.log('Writing Auth config to ' + configFilePath + ' ...');
        fs.writeFileSync(configFilePath, JSON2.stringify(trustedAuthTables[auth.id], null, '\t'), 'utf8');
    }
}

// generate properties files
function generatePropertiesFiles() {
    for (var i = 0; i < authList.length; i++) {
        var auth = authList[i];
        var authDBDir = '../databases/auth' + auth.id;
        var authKeystorePrefix = authDBDir + '/my_keystores/Auth' + auth.id;
        var properties = {
            'auth_id': auth.id,
            'host_name': '0.0.0.0',
            'entity_tcp_port': auth.tcpPort,
            'entity_tcp_port_timeout': 20000,
            'entity_udp_port': auth.udpPort,
            'entity_udp_port_timeout': 20000,
            'trusted_auth_port': auth.authPort,
            'trusted_auth_port_idle_timeout': 600000,
            'contextual_callback_port': auth.callbackPort,
            'contextual_callback_port_idle_timeout': 20000,
            'contextual_callback_enabled': auth.contextualCallbackEnabled,
            'entity_key_store_path': authKeystorePrefix + 'Entity.pfx',
            'internet_key_store_path': authKeystorePrefix + 'Internet.pfx',
            'database_key_store_path': authKeystorePrefix + 'Database.pfx',
            'database_encryption_key_path': authKeystorePrefix + 'Database.bin',
            'trusted_ca_cert_paths': '../credentials/ca/CACert.pem',
            'auth_database_dir': authDBDir,
            'auth_db_protection_method': auth.dbProtectionMethod,
            // currently default is true, set false only when this is given by the graph file
            'backup_enabled': (auth.backupEnabled != null && !auth.backupEnabled) ? false : true,
            // Bluetooth is turned off by default.
            'bluetooth_enabled': false,
            // currently default is false
            'qps_throttling_enabled': auth.capacityQpsLimit == null ? false : true,
            'qps_limit': auth.capacityQpsLimit == null ? 10 : auth.capacityQpsLimit/60.0,
            'qps_calculation_bucket_size_in_sec': 60
        };
        var strProperties = '';
        for (var key in properties) {
            strProperties += (key + '=' + properties[key] + '\n');
        }
        var propertiesFilePath = AUTH_PROPERTIES_DIR + 'exampleAuth' + auth.id + '.properties';
        console.log('Writing Auth properties to ' + propertiesFilePath + ' ...');
        fs.writeFileSync(propertiesFilePath, strProperties, 'utf8');
    }
}
// generate configs
createConfigDirs();
generateRegisteredEntityTables();
generateCommunicationPolicyTables();
generateTrustedAuthTables();
generatePropertiesFiles();
generateFileSharingInfoTables();
