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

var cryptoInfo = {
    publicKeyCryptoSpec: { sign: 'RSA-SHA256' },
    distCryptoSpec: { cipher: 'AES-128-CBC', mac: 'SHA256' },
    sessionCryptoSpec: { cipher: 'AES-128-CBC', mac: 'SHA256' }
};

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

var tcpServerInfoList = [];
var udpServerInfoList = [];
var safetyCriticalServerInfoList = [];

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

function getAuthInfo(netId, entityName) {
    var authInfo = {};
    authInfo.id = 100 + netId;
    authInfo.host = 'localhost';
    authInfo.port = getNetPortBase(netId) + 900;
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
            "sign": "RSA-SHA256"
        };
    }
    cryptoInfo.distCryptoSpec = {
        "cipher": "AES-128-CBC",
        "mac": "SHA256"
    };
    cryptoInfo.sessionCryptoSpec = {
        "cipher": "AES-128-CBC",
        "mac": "SHA256"
    };
    if (entityName.toLowerCase().includes('safetycritical')) {
        cryptoInfo.sessionCryptoSpec.diffieHellman = "secp128r2";
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

function getEntityConfig(netId, entity) {
    var entityConfig = {};
    entityConfig.entityInfo = getEntityInfo(netId, entity.name);
    entityConfig.authInfo = getAuthInfo(netId, entity.name);
    entityConfig.cryptoInfo = getCryptoInfo(entity.name);
    if (entity.name.toLowerCase().includes('client')) {
        var targetServerInfoList = getTargetServerInfoList(1, entity.name);
        targetServerInfoList = targetServerInfoList.concat(getTargetServerInfoList(2, entity.name));
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
    var configFilePath = entityFullName.substring(0, separatorIndex)
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
        var dirName = getNetName(netId);
        if (!fs.existsSync(dirName)){
            fs.mkdirSync(dirName);
        }
        for (var i = 0; i < entityList.length; i++) {
            netConfig.entityConfigList.push(getEntityConfig(netId, entityList[i]));
        }
        netConfigList.push(netConfig);
    }
    return netConfigList;
}

function generateEntityConfigs(netConfigList) {
    for (var i = 0; i < netConfigList.length; i++) {
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

function convertToRegisteredEntity(entityConfig) {
    var registeredEntity = {};
    registeredEntity.Name = entityConfig.entityInfo.name;
    registeredEntity.Group = entityConfig.entityInfo.group;
    registeredEntity.DistProtocol = entityConfig.entityInfo.distProtocol;
    // Resource-constrained entity
    if (entityConfig.entityInfo.usePermanentDistKey) {
        registeredEntity.UsePermanentDistKey = true;
        registeredEntity.MaxSessionKeysPerRequest = 30;
        var permanentDistKey = entityConfig.entityInfo.permanentDistKey;
        registeredEntity.DistValidityPeriod = permanentDistKey.validity;
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
        // MaxSessionKeysPerRequest
        if (entityConfig.entityInfo.name.toLowerCase().includes('server')) {
            registeredEntity.MaxSessionKeysPerRequest = 1;
        }
        else {
            registeredEntity.MaxSessionKeysPerRequest = 5;
        }
        // DistValidityPeriod
        if (entityConfig.entityInfo.name.toLowerCase().includes('pt')) {
            registeredEntity.DistValidityPeriod = '3*sec';
        }
        else {
            registeredEntity.DistValidityPeriod = '1*hour';
        }
        var separatorIndex = entityConfig.entityInfo.privateKey.lastIndexOf('/');
        // Public key setting
        registeredEntity.PublKeyFile = 'entity_certs'
            + entityConfig.entityInfo.privateKey.substring(separatorIndex).replace('Key.pem', 'Cert.pem');
    }

    registeredEntity.DistCryptoSpec = entityConfig.cryptoInfo.distCryptoSpec.cipher
        + ':' + entityConfig.cryptoInfo.distCryptoSpec.mac;
    return registeredEntity;
}

function convertToRegisteredEntityTable(netConfigList) {
    var registeredEntityTableList = [];
    for (var i = 0; i < netConfigList.length; i++) {
        var netConfig = netConfigList[i];
        var registeredEntityTable = {
            'authId': 100 + netConfig.netId,
            'registeredEntityList': []
        };
        for (var j = 0; j < netConfig.entityConfigList.length; j++) {
            registeredEntityTable.registeredEntityList.push(
                convertToRegisteredEntity(netConfig.entityConfigList[j]));
        }
        registeredEntityTableList.push(registeredEntityTable);
    }
    return registeredEntityTableList;
}

function generateRegisteredEntityTables(registeredEntityTableList) {
    var dirName = 'Auth';
    if (!fs.existsSync(dirName)){
        fs.mkdirSync(dirName);
    }
    for (var i = 0; i < registeredEntityTableList.length; i++) {
        var registeredEntityTable = registeredEntityTableList[i];
        var fileName = 'Auth' + registeredEntityTable.authId + 'RegisteredEntityTable.config';
        var configFilePath = dirName + '/' + fileName;
        console.log('Writing entityConfig to ' + configFilePath + ' ...');
        fs.writeFileSync(configFilePath,
            JSON2.stringify(registeredEntityTable.registeredEntityList, null, '\t'),
            'utf8'
        );
    }
}

var totalNumberOfNets = 2;
var netConfigList = getEntityConfigs(totalNumberOfNets);
//console.log(JSON2.stringify(netConfigList[0].entityConfigList, null, '\t'));
generateEntityConfigs(netConfigList);
var registeredEntityTableList = convertToRegisteredEntityTable(netConfigList);
generateRegisteredEntityTables(registeredEntityTableList);
//console.log(JSON2.stringify(registeredEntityTableList, null, '\t'));
