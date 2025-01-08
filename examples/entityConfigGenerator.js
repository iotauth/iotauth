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
 * Generator for configuration files for Auth and entity
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

var authList = graph.authList;
var auths = {};
for (var i = 0; i < authList.length; i++) {
	var auth = authList[i];
	auths[auth.id] = auth;
}

// generate server info lists
var entityList = graph.entityList;
var tcpServerInfoList = [];
var udpServerInfoList = [];
var diffieHellmanServerInfoList = [];
for (var i = 0; i < entityList.length; i++) {
	var entity = entityList[i];
	if (entity.host != null && entity.port != null) {
		var serverInfo = {name: entity.name, host: entity.host, port: entity.port};
		if (entity.diffieHellman != null) {
			diffieHellmanServerInfoList.push(serverInfo);
		}
		else if (entity.distProtocol == 'UDP') {
			udpServerInfoList.push(serverInfo);
		}
		else {
			tcpServerInfoList.push(serverInfo);
		}
	}
}

// generate entity configs
var assignments = graph.assignments;
function getKeyPath(subDir, credentialPrefix, credentialSuffix) {
	const ENTITY_CREDS_DIR = '../../credentials/keys/';
	return ENTITY_CREDS_DIR + subDir + '/' + credentialPrefix + credentialSuffix;
}
function getEntityInfo(entity) {
	var entityInfo = {
		name: entity.name,
		group: entity.group,
		distProtocol: entity.distProtocol,
		usePermanentDistKey: entity.usePermanentDistKey,
		connectionTimeout: entity.distProtocol == 'UDP' ? 10000 : 5000
	};
	if (entity.usePermanentDistKey == true) {
		entityInfo.permanentDistKey = {
			cipherKey: getKeyPath(entity.netName, entity.credentialPrefix, 'CipherKey.key'),
			macKey: getKeyPath(entity.netName, entity.credentialPrefix, 'MacKey.key'),
			validity: '365*day'
		};
	}
	else {
		var credentialSuffix = 'Key.pem';
		if (entity.inDerFormat == true) {
			credentialSuffix = 'Key.der';	
		}
		entityInfo.privateKey = getKeyPath(entity.netName, entity.credentialPrefix, 'Key.pem');
	}
	return entityInfo;
}
function getAuthInfo(entity) {
	var auth = auths[assignments[entity.name]];
	return {
		id: auth.id,
		host: auth.entityHost,
		port: entity.distProtocol == 'TCP' ? auth.tcpPort : auth.udpPort,
		publicKey: '../../auth_certs/Auth' + auth.id + 'EntityCert.pem'
	};
}
function getMigrationInfo(entity) {
	var getMigrationInfoList = [];
	for (var i = 0; i < entity.backupToAuthIds.length; i++) {
		var auth = auths[entity.backupToAuthIds[i]];
		if (auth != null) {
			var migrationInfo = {
				host: auth.entityHost,
				port: entity.distProtocol == 'TCP' ? auth.tcpPort : auth.udpPort
			};
			getMigrationInfoList.push(migrationInfo);
		}
	}
	return getMigrationInfoList;
}
function getCryptoInfo(entity) {
    var cryptoInfo = {};
    if (entity.usePermanentDistKey != true) {
        cryptoInfo.publicKeyCryptoSpec = {
            'sign': common.DEFAULT_SIGN,
            'padding': common.DEFAULT_RSA_PADDING,
            'keySize': common.DEFAULT_RSA_KEY_SIZE
        };
        if (entity.diffieHellman != null) {
            cryptoInfo.publicKeyCryptoSpec.diffieHellman = entity.diffieHellman;
        }
    }
    cryptoInfo.distributionCryptoSpec = {
        'cipher': entity.distributionCryptoSpec.cipher,
        'mac': entity.distributionCryptoSpec.mac,
    };
    cryptoInfo.sessionCryptoSpec = {
        'cipher': entity.sessionCryptoSpec.cipher,
        'mac': entity.sessionCryptoSpec.mac,
    };
    if (entity.diffieHellman != null) {
        cryptoInfo.sessionCryptoSpec.diffieHellman = entity.diffieHellman;
    }
    return cryptoInfo;
}
function getTargetServerInfoList(entity) {
	if (entity.targetServerInfoList != null) {
		return entity.targetServerInfoList;
	}
	var targetServerInfoList = [];
	if (entity.diffieHellman != null) {
		targetServerInfoList = targetServerInfoList.concat(diffieHellmanServerInfoList);
	}
	else if (entity.distProtocol == 'TCP') {
		targetServerInfoList = targetServerInfoList.concat(tcpServerInfoList);
	}
	else {
		targetServerInfoList = targetServerInfoList.concat(udpServerInfoList);
	}
	return targetServerInfoList;
}
function writeEntityConfigToFile(entity, entityConfig) {
    var entityFullName = entityConfig.entityInfo.name;
    var separatorIndex = entityFullName.indexOf('.');
	const ENTITY_CONFIG_DIR = PROJ_ROOT_DIR + 'entity/node/example_entities/configs/'
		+ entity.netName + '/';
	execFileSync('mkdir', ['-p', ENTITY_CONFIG_DIR]);
    var configFilePath = ENTITY_CONFIG_DIR + entityFullName.substring(separatorIndex + 1) + '.config';
    console.log('Writing entityConfig to ' + configFilePath + ' ...');
    fs.writeFileSync(configFilePath,
        JSON2.stringify(entityConfig, null, '\t'),
        'utf8'
    );
}
for (var i = 0; i < entityList.length; i++) {
	var entity = entityList[i];
	if (entity.group.startsWith('Pt')) {
		continue;
	}
	var entityConfig = {
		entityInfo: getEntityInfo(entity),
		authInfo: getAuthInfo(entity),
		migrationInfo: getMigrationInfo(entity),
		cryptoInfo: getCryptoInfo(entity)
	};
	if (entity.host != null && entity.port != null) {
		entityConfig.listeningServerInfo = {
			host: entity.host,
			port: entity.port
		};
	}
	else {
		entityConfig.targetServerInfoList = getTargetServerInfoList(entity);
	}
	writeEntityConfigToFile(entity, entityConfig);
	//console.log(entityConfig);
}
