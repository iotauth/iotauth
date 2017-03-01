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
var JSON2 = require('JSON2');

// this is where the entity config files are generated
var ENTITY_CONFIG_DIR = 'entity/node/example_entities/configs/';

var AUTH_DB_DIR = 'auth/databases/';

var DEFAULT_SIGN = 'RSA-SHA256';
var DEFAULT_RSA_KEY_SIZE = 256;     // 2048 bits
var DEFAULT_RSA_PADDING = 'RSA_PKCS1_PADDING';
var DEFAULT_CIPHER = 'AES-128-CBC';
var DEFAULT_MAC = 'SHA256';
// generates 384-bit (48-byte) secret, 128 bit for cipher, 256 bit for MAC
var DEFAULT_DH = 'secp384r1';


var entityList = [
    { name: 'client' },
    { name: 'ptClient' },
    { name: 'rcClient' },
    { name: 'udpClient' },
    { name: 'safetyCriticalClient' },
    { name: 'rcUdpClient' },
    { name: 'server', port: 100 },
    { name: 'ptServer', port: 200 },
    { name: 'rcServer', port: 300 },
    { name: 'udpServer', port: 400 },
    { name: 'safetyCriticalServer', port: 500 },
    { name: 'rcUdpServer', port: 600 },
    { name: 'ptPublisher' },
    { name: 'ptSubscriber' }
];

function capitalizeFirstLetter(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}

function getNetName(netId) {
    return 'net' + netId;
}

function getKeyPath(netId, entityName, keySuffix) {
    return '../../credentials/keys/' + getNetName(netId) + '/'
        + capitalizeFirstLetter(getNetName(netId)) + '.'
        + capitalizeFirstLetter(entityName) + keySuffix;
}

function getEntityInfo(netId, entityName) {
    var entityInfo = {};
    entityInfo.name = getNetName(netId) + '.' + entityName;
    if (entityName.toLowerCase().includes('ptclient')) {
        entityInfo.group = 'PtClients';
    }
    else if (entityName.toLowerCase().includes('ptserver')) {
        entityInfo.group = 'PtServers';
    }
    else if (entityName.toLowerCase().includes('ptpublisher')) {
        entityInfo.group = 'PtPublishers';
    }
    else if (entityName.toLowerCase().includes('ptsubscriber')) {
        entityInfo.group = 'PtSubscribers';
    }
    else if (entityName.toLowerCase().includes('client')) {
        entityInfo.group = 'Clients';
    }
    else if (entityName.toLowerCase().includes('server')) {
        entityInfo.group = 'Servers';
    }
    if (entityName.toLowerCase().includes('udp')) {
        entityInfo.distProtocol = 'UDP';
    }
    else {
        entityInfo.distProtocol = 'TCP';
    }
    if (entityName.toLowerCase().includes('rc')) {
        entityInfo.usePermanentDistKey = true;
        entityInfo.permanentDistKey = {
            'cipherKey': getKeyPath(netId, entityName, 'CipherKey.key'),
            'macKey': getKeyPath(netId, entityName, 'MacKey.key'),
            'validity': '365*day'
        }
    }
    else {
        entityInfo.usePermanentDistKey = false;
    }
    entityInfo.privateKey = getKeyPath(netId, entityName, 'Key.pem');
    return entityInfo;
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

function getAuthInfo(netId, entityName) {
    var authInfo = {};
    authInfo.id = getAuthId(netId);
    authInfo.host = 'localhost';
    authInfo.port = getAuthPortBase(netId);
    if (entityName.toLowerCase().includes('udp')) {
        authInfo.port += 2;
    }
    if (!entityName.toLowerCase().includes('rc')) {
        authInfo.publicKey = '../../auth_certs/Auth' + authInfo.id + 'EntityCert.pem';
    }
    return authInfo;
}

function getCryptoInfo(entityName) {
    var cryptoInfo = {};
    if (!entityName.toLowerCase().includes('rc')) {
        cryptoInfo.publicKeyCryptoSpec = {
            'sign': DEFAULT_SIGN,
            'padding': DEFAULT_RSA_PADDING,
            'keySize': DEFAULT_RSA_KEY_SIZE
        };
        if (entityName.toLowerCase().includes('safetycritical')) {
            cryptoInfo.publicKeyCryptoSpec.diffieHellman = DEFAULT_DH;
        }
    }
    cryptoInfo.distributionCryptoSpec = {
        'cipher': DEFAULT_CIPHER,
        'mac': DEFAULT_MAC
    };
    cryptoInfo.sessionCryptoSpec = {
        'cipher': DEFAULT_CIPHER,
        'mac': DEFAULT_MAC
    };
    if (entityName.toLowerCase().includes('safetycritical')) {
        cryptoInfo.sessionCryptoSpec.diffieHellman = DEFAULT_DH;
    }
    return cryptoInfo;
}

function getTargetServerInfoList(netId, entityName) {
    var targetServerInfoList = [];
    for (var i = 0; i < entityList.length; i++) {
        if (!entityList[i].name.toLowerCase().includes('server')) {
            continue;
        }
        var serverInfo = {};
        serverInfo.name = getNetName(netId) + '.' + entityList[i].name;
        serverInfo.port = getNetPortBase(netId) + entityList[i].port;
        serverInfo.host = 'localhost';
        if (entityList[i].name.toLowerCase().includes('udp')) {
            if (entityName.toLowerCase().includes('udp')) {
                targetServerInfoList.push(serverInfo);
            }
        }
        else if (entityList[i].name.toLowerCase().includes('safetycritical')) {
            if (entityName.toLowerCase().includes('safetycritical')) {
                targetServerInfoList.push(serverInfo);
            }
        }
        else {
            if (!entityName.toLowerCase().includes('udp') &&
                !entityName.toLowerCase().includes('safetycritical')) {
                    targetServerInfoList.push(serverInfo);
            }

        }
    }
    return targetServerInfoList;
}

function getListeningServerInfo(netId, server) {
    var listeningServerInfo = {};
    listeningServerInfo.host = 'localhost';
    listeningServerInfo.port = getNetPortBase(netId) + server.port;
    return listeningServerInfo;
}

function getEntityConfig(netId, entity, numNets) {
    var entityConfig = {};
    entityConfig.entityInfo = getEntityInfo(netId, entity.name);
    entityConfig.authInfo = getAuthInfo(netId, entity.name);
    entityConfig.cryptoInfo = getCryptoInfo(entity.name);
    if (entity.name.toLowerCase().includes('client')) {
        var targetServerInfoList = [];
        for (var otherNetId = 1; otherNetId <= numNets; otherNetId++) {
            targetServerInfoList = targetServerInfoList.concat(getTargetServerInfoList(otherNetId, entity.name));
        }
        entityConfig.targetServerInfoList = targetServerInfoList;
    }
    if (entity.name.toLowerCase().includes('server')) {
        entityConfig.listeningServerInfo = getListeningServerInfo(netId, entity);
    }
    return entityConfig;
}

function writeEntityConfigToFile(entityConfig) {
    var entityFullName = entityConfig.entityInfo.name;
    var separatorIndex = entityFullName.indexOf('.');
    var configFilePath = ENTITY_CONFIG_DIR + entityFullName.substring(0, separatorIndex)
        + '/' + entityFullName.substring(separatorIndex + 1) + '.config';
    console.log('Writing entityConfig to ' + configFilePath + ' ...');
    fs.writeFileSync(configFilePath,
        JSON2.stringify(entityConfig, null, '\t'),
        'utf8'
    );
}

function getEntityConfigs(numNets) {
    var netConfigList = [];
    for (var netId = 1; netId <= numNets; netId++) {
        var netConfig = {
            'netId': netId,
            'entityConfigList': []
        };
        for (var i = 0; i < entityList.length; i++) {
            netConfig.entityConfigList.push(getEntityConfig(netId, entityList[i], numNets));
        }
        netConfigList.push(netConfig);
    }
    return netConfigList;
}

function generateEntityConfigs(netConfigList) {
    if (!fs.existsSync(ENTITY_CONFIG_DIR)) {
        fs.mkdirSync(ENTITY_CONFIG_DIR);
    }
    for (var i = 0; i < netConfigList.length; i++) {
        var dirName = getNetName(netConfigList[i].netId);
        if (!fs.existsSync(ENTITY_CONFIG_DIR + dirName)){
            fs.mkdirSync(ENTITY_CONFIG_DIR + dirName);
        }
        var netConfig = netConfigList[i];
        for (var j = 0; j < netConfig.entityConfigList.length; j++) {
            var entityConfig = netConfig.entityConfigList[j];
            if (entityConfig.entityInfo.name.includes('pt')) {
                continue;
            }
            writeEntityConfigToFile(entityConfig);
        }
    }
}

function convertToRegisteredEntity(entityConfig, backupTo) {
    var registeredEntity = {};
    registeredEntity.Name = entityConfig.entityInfo.name;
    registeredEntity.Group = entityConfig.entityInfo.group;
    registeredEntity.DistProtocol = entityConfig.entityInfo.distProtocol;
    // Resource-constrained entity
    if (entityConfig.entityInfo.usePermanentDistKey) {
        registeredEntity.UsePermanentDistKey = true;
        registeredEntity.MaxSessionKeysPerRequest = 30;
        var permanentDistKey = entityConfig.entityInfo.permanentDistKey;
        registeredEntity.DistKeyValidityPeriod = permanentDistKey.validity;
        // For resource-constrained only
        var separatorIndex = permanentDistKey.cipherKey.lastIndexOf('/');
        registeredEntity.DistCipherKeyFilePath = 'entity_keys'
            + permanentDistKey.cipherKey.substring(separatorIndex);
        separatorIndex = permanentDistKey.macKey.lastIndexOf('/');
        registeredEntity.DistMacKeyFilePath = 'entity_keys'
            + permanentDistKey.macKey.substring(separatorIndex);
    }
    // Not resource-constrained entity
    else {
        registeredEntity.UsePermanentDistKey = false;
        registeredEntity.PublicKeyCryptoSpec = entityConfig.cryptoInfo.publicKeyCryptoSpec.sign;
        // with additional Diffie-Hellman key exchange for key distribution
        if (entityConfig.cryptoInfo.publicKeyCryptoSpec.diffieHellman) {
            registeredEntity.PublicKeyCryptoSpec += (':DH-' + entityConfig.cryptoInfo.publicKeyCryptoSpec.diffieHellman);
        }
        // MaxSessionKeysPerRequest
        if (entityConfig.entityInfo.name.toLowerCase().includes('server')) {
            registeredEntity.MaxSessionKeysPerRequest = 1;
        }
        else {
            registeredEntity.MaxSessionKeysPerRequest = 5;
        }
        // DistKeyValidityPeriod
        if (entityConfig.entityInfo.name.toLowerCase().includes('pt')) {
            registeredEntity.DistKeyValidityPeriod = '3*sec';
        }
        else {
            registeredEntity.DistKeyValidityPeriod = '1*hour';
        }
        var separatorIndex = entityConfig.entityInfo.privateKey.lastIndexOf('/');
        // Public key setting
        registeredEntity.PublicKeyFile = 'entity_certs'
            + entityConfig.entityInfo.privateKey.substring(separatorIndex).replace('Key.pem', 'Cert.pem');
    }

    registeredEntity.DistCryptoSpec = entityConfig.cryptoInfo.distributionCryptoSpec.cipher
        + ':' + entityConfig.cryptoInfo.distributionCryptoSpec.mac;

    registeredEntity.Active = true;
    registeredEntity.BackupToAuthID = backupTo;
    registeredEntity.BackupFromAuthID = -1;
    return registeredEntity;
}

function convertToRegisteredEntityTable(netConfigList) {
    var registeredEntityTableList = [];
    for (var i = 0; i < netConfigList.length; i++) {
        var netConfig = netConfigList[i];
        var registeredEntityTable = {
            'authId': getAuthId(netConfig.netId),
            'registeredEntityList': []
        };
        var backupToAuthID = -1;
        if (netConfigList.length > 1) {
            var otherNetId = netConfig.netId % netConfigList.length + 1;
            backupToAuthID = getAuthId(otherNetId);
        }
        for (var j = 0; j < netConfig.entityConfigList.length; j++) {
            registeredEntityTable.registeredEntityList.push(
                convertToRegisteredEntity(netConfig.entityConfigList[j], backupToAuthID)
            );
        }
        registeredEntityTableList.push(registeredEntityTable);
    }
    return registeredEntityTableList;
}

function generateRegisteredEntityTables(registeredEntityTableList) {
    for (var i = 0; i < registeredEntityTableList.length; i++) {
        var registeredEntityTable = registeredEntityTableList[i];
        var dirName = AUTH_DB_DIR + 'auth' + registeredEntityTable.authId + '/configs/';
        if (!fs.existsSync(dirName)){
            fs.mkdirSync(dirName);
        }
        var fileName = 'Auth' + registeredEntityTable.authId + 'RegisteredEntityTable.config';
        var configFilePath = dirName + fileName;
        console.log('Writing Auth config to ' + configFilePath + ' ...');
        fs.writeFileSync(configFilePath,
            JSON2.stringify(registeredEntityTable.registeredEntityList, null, '\t'),
            'utf8'
        );
    }
}

function addServerClientPolicy(list, requestingGroup, target, absoluteValidity, relativeValidity) {
    list.push({
        'RequestingGroup': requestingGroup,
        'TargetType': 'Group',
        'Target': target,
        'MaxNumSessionKeyOwners': 2,
        'SessionCryptoSpec': DEFAULT_CIPHER + ':' + DEFAULT_MAC,
        'AbsoluteValidity': absoluteValidity,
        'RelativeValidity': relativeValidity
    });
}

function addPubSubPolicy(list, requestingGroup, isPub) {
    list.push({
        'RequestingGroup': requestingGroup,
        'TargetType': isPub ? 'PubTopic' : 'SubTopic',
        'Target': 'Ptopic',
        'MaxNumSessionKeyOwners': 64,
        'SessionCryptoSpec': DEFAULT_CIPHER + ':' + DEFAULT_MAC,
        'AbsoluteValidity': '6*hour',
        'RelativeValidity': '3*hour'
    });
}

function generateCommunicationPolicyTables(numberOfAuths) {
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

    for (var netId = 1; netId <= numberOfAuths; netId++) {
        var authId = getAuthId(netId);
        var dirName = AUTH_DB_DIR + 'auth' + authId + '/configs/';
        var fileName = 'Auth' + authId + 'CommunicationPolicyTable.config';
        var configFilePath = dirName + fileName;
        console.log('Writing Auth config to ' + configFilePath + ' ...');
        fs.writeFileSync(configFilePath, JSON2.stringify(policyList, null, '\t'), 'utf8');
    }
}

function generateTrustedAuthTables(numberOfAuths) {
    for (var netId = 1; netId <= numberOfAuths; netId++) {
        var myAuthId = getAuthId(netId);
        var trustedAuthList = [];
        for (var otherNetId = 1; otherNetId <= numberOfAuths; otherNetId++) {
            if (netId == otherNetId) {
                continue;
            }
            var otherAuthId = getAuthId(otherNetId);
            trustedAuthList.push({
                'ID': otherAuthId,
                'Host': 'localhost',
                'Port': getAuthPortBase(otherNetId) + 1,
                'CertificatePath': 'trusted_auth_certs/Auth' + otherAuthId + 'InternetCert.pem'
            });
        }
        var dirName = AUTH_DB_DIR + 'auth' + myAuthId + '/configs/';
        var fileName = 'Auth' + myAuthId + 'TrustedAuthTable.config';
        var configFilePath = dirName + fileName;
        console.log('Writing Auth config to ' + configFilePath + ' ...');
        fs.writeFileSync(configFilePath, JSON2.stringify(trustedAuthList, null, '\t'), 'utf8');
    }
}

function generatePropertiesFiles(numberOfAuths, authDBProtectionMethod) {
    for (var netId = 1; netId <= numberOfAuths; netId++) {
        var authId = getAuthId(netId);
        var authPortBase = getAuthPortBase(netId);
        var authDBDir = '../databases/auth' + authId;
        var authKeystorePrefix = authDBDir + '/my_keystores/Auth' + authId;
        var properties = {
            'auth_id': authId,
            'host_name': '0.0.0.0',
            'entity_tcp_port': authPortBase,
            'entity_tcp_port_timeout': 2000,
            'entity_udp_port': authPortBase + 2, 
            'entity_udp_port_timeout': 5000,
            'trusted_auth_port': authPortBase + 1,
            'trusted_auth_port_idle_timeout': 600000,
            'entity_key_store_path': authKeystorePrefix + 'Entity.pfx',
            'internet_key_store_path': authKeystorePrefix + 'Internet.pfx',
            'database_key_store_path': authKeystorePrefix + 'Database.pfx',
            'database_encryption_key_path': authKeystorePrefix + 'Database.bin',
            'trusted_ca_cert_paths': '../credentials/ca/CACert.pem',
            'auth_database_dir': authDBDir,
            'auth_db_protection_method': authDBProtectionMethod
        };
        var strProperties = '';
        for (var key in properties) {
            strProperties += (key + '=' + properties[key] + '\n');
        }
        var propertiesDir = 'auth/properties/';
        var propertiesFilePath = propertiesDir + 'exampleAuth' + authId + '.properties';
        console.log('Writing Auth properties to ' + propertiesFilePath + ' ...');
        fs.writeFileSync(propertiesFilePath, strProperties, 'utf8');
    }
}

if (process.argv.length <= 3) {
    console.log('Error: please specify [total number of networks] and [Auth DB protection method]');
    process.exit(1);
}

var totalNumberOfNets = parseInt(process.argv[2]);
var authDBProtectionMethod = parseInt(process.argv[3]);
console.log(totalNumberOfNets);
var netConfigList = getEntityConfigs(totalNumberOfNets);
//console.log(JSON2.stringify(netConfigList[0].entityConfigList, null, '\t'));
generateEntityConfigs(netConfigList);
var registeredEntityTableList = convertToRegisteredEntityTable(netConfigList);
generateRegisteredEntityTables(registeredEntityTableList);
generateCommunicationPolicyTables(totalNumberOfNets);
generateTrustedAuthTables(totalNumberOfNets);
generatePropertiesFiles(totalNumberOfNets, authDBProtectionMethod);

//console.log(JSON2.stringify(registeredEntityTableList, null, '\t'));
