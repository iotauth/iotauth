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

var serverList = [
    { name: 'server', port: 100 },
    { name: 'ptServer', port: 200 },
    { name: 'rcServer', port: 300 },
    { name: 'udpServer', port: 400 },
    { name: 'safetyCriticalServer', port: 500 },
    { name: 'rcUdpServer', port: 600 }
];

var clientList = [
    { name: 'client' },
    { name: 'ptClient' },
    { name: 'rcClient' },
    { name: 'udpClient' },
    { name: 'safetyCriticalClient' },
    { name: 'rcUdpClient' }
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
        + capitalizeFirstLetter(entityName) + keySuffix;
}

function getEntityInfo(netId, entityName) {
    var entityInfo = {};
    entityInfo.name = getNetName(netId) + '.' + entityName;
    if (entityName.toLowerCase().includes('client')) {
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
    for (var i = 0; i < serverList.length; i++) {
        var serverInfo = {};
        serverInfo.name = getNetName(netId) + '.' + serverList[i].name;
        serverInfo.port = getNetPortBase(netId) + serverList[i].port;
        serverInfo.host = 'localhost';
        if (serverList[i].name.toLowerCase().includes('udp')) {
            if (entityName.toLowerCase().includes('udp')) {
                targetServerInfoList.push(serverInfo);
            }
        }
        else if (serverList[i].name.toLowerCase().includes('safetycritical')) {
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
            'clientConfigList': [],
            'serverConfigList': []
        };
        var dirName = getNetName(netId);
        if (!fs.existsSync(dirName)){
            fs.mkdirSync(dirName);
        }
        for (var i = 0; i < clientList.length; i++) {
            netConfig.clientConfigList.push(getEntityConfig(netId, clientList[i]));
        }
        for (var i = 0; i < serverList.length; i++) {
            netConfig.serverConfigList.push(getEntityConfig(netId, serverList[i]));
        }
        netConfigList.push(netConfig);
    }
    return netConfigList;
}

function generateEntityConfigs(netConfigList) {
    for (var i = 0; i < netConfigList.length; i++) {
            var netConfig = netConfigList[i];
        for (var j = 0; j < netConfig.clientConfigList.length; j++) {
            var clientConfig = netConfig.clientConfigList[j];
            if (clientConfig.entityInfo.name.includes('pt')) {
                continue;
            }
            writeEntityConfigToFile(clientConfig);
        }
        for (var j = 0; j < netConfig.serverConfigList.length; j++) {
            var serverConfig = netConfig.serverConfigList[j];
            if (serverConfig.entityInfo.name.includes('pt')) {
                continue;
            }
            writeEntityConfigToFile(serverConfig);
        }
    }
}

function convertToRegisteredEntity(entityConfig) {
    var registeredEntity = {};
    registeredEntity.Name = entityConfig.entityInfo.name;
    registeredEntity.Group = entityConfig.entityInfo.group;
    registeredEntity.DistProtocol = entityConfig.entityInfo.distProtocol;
    if (entityConfig.entityInfo.usePermanentDistKey) {
        registeredEntity.UsePermanentDistKey = 1;
        registeredEntity.MaxSessionKeysPerRequest = 30;
    }
    else {
        registeredEntity.UsePermanentDistKey = 0;
        if (entityConfig.entityInfo.name.toLowerCase().includes('server')) {
            registeredEntity.MaxSessionKeysPerRequest = 1;
        }
        else {
            registeredEntity.MaxSessionKeysPerRequest = 5;
        }
    }
    var separatorIndex = entityConfig.entityInfo.name.lastIndexOf('/');
    registeredEntity.PublKeyFile = 'certs/'
        + entityConfig.entityInfo.name.substring(separatorIndex + 1);

    if (entityConfig.entityInfo.name.toLowerCase().includes('pt')) {
        registeredEntity.DistValidityPeriod = '3*sec';
    }
    else {
        registeredEntity.DistValidityPeriod = '1*hour';
    }
}

function convertToRegisteredEntityTable(netConfigList) {
    var registeredEntityTableList = [];
    for (var i = 0; i < netConfigList.length; i++) {
            var netConfig = netConfigList[i];
        for (var j = 0; j < netConfig.clientConfigList.length; j++) {
            //writeEntityConfigToFile(clientConfig);
        }
        for (var j = 0; j < netConfig.serverConfigList.length; j++) {
            //writeEntityConfigToFile(serverConfig);
        }
    }

}

var totalNumberOfNets = 2;
var netConfigList = getEntityConfigs(totalNumberOfNets);
//console.log(JSON2.stringify(netConfigList[0].clientConfigList, null, '\t'));
generateEntityConfigs(netConfigList);
