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

for (var i = 0; i < DEFAULT_ENTITY_LIST.length; i++) {
	var entity = DEFAULT_ENTITY_LIST[i];
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

var numNets = 2;

var authList = [];
var entityList = [];
var authTrusts = [];
var assignments = {};

/*
	dbProtectionMethod: values
    DEBUG(0),
    ENCRYPT_CREDENTIALS(1),
    ENCRYPT_ENTIRE_DB(2);
*/
const AUTH_UDP_PORT_OFFSET = 2;
const TRUSTED_AUTH_PORT_OFFSET = 1;
for (var netId = 1; netId <= numNets; netId++) {
	var authId = getAuthId(netId);
	var authInfo = {
		id: authId,
		entityHost: 'localhost',
		authHost: 'localhost',
		tcpPort: getAuthPortBase(netId),
		udpPort: getAuthPortBase(netId) + AUTH_UDP_PORT_OFFSET,
		authPort: getAuthPortBase(netId) + TRUSTED_AUTH_PORT_OFFSET,
		dbProtectionMethod: 1
	};
	authList.push(authInfo);
	for (var otherNetId = netId + 1; otherNetId <= numNets; otherNetId++) {
		var otherAuthId = getAuthId(otherNetId);
		var authTrust = {
			id1: authId,
			id2: otherAuthId
		};
		authTrusts.push(authTrust)
	}
	var netEntityList = cloneJson(DEFAULT_ENTITY_LIST);
	for (var i = 0; i < netEntityList.length; i++) {
		entity = netEntityList[i];
		entity.netName = 'net' + netId;
		entity.credentialPrefix = 'Net' + netId + '.' + capitalizeFirstLetter(entity.name);
		entity.name = 'net' + netId + '.' + entity.name;
		if (entity.port != null) {
			entity.port = getNetPortBase(netId) + entity.port;
			entity.host = 'localhost';
		}
		entity.backupToAuthId = getAuthId((netId % numNets) + 1);
		assignments[entity.name] = authId;
		entityList.push(entity);
	}
}

var graph = {
	authList: authList,
	authTrusts: authTrusts,
	assignments: assignments,
	entityList: entityList
};

fs.writeFileSync('default.graph', 
	JSON2.stringify(graph, null, '\t'),
	'utf8'
);
