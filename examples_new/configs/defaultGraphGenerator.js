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
	}
}

var numNets = 3;

var authList = [];
var entityList = [];
var authTrusts = [];
var assignments = {};

for (var netId = 1; netId <= numNets; netId++) {
	var authId = 100 + netId;
	var authInfo = {
		"id": authId
	};
	authList.push(authInfo);
	for (var otherNetId = netId + 1; otherNetId <= numNets; otherNetId++) {
		var otherAuthId = 100 + otherNetId;
		var authTrust = {
			"id1": authId,
			"id2": otherAuthId
		};
		authTrusts.push(authTrust)
	}
	var netEntityList = cloneJson(DEFAULT_ENTITY_LIST);
	for (var i = 0; i < netEntityList.length; i++) {
		entity = netEntityList[i];
		entity.netName = 'net' + netId;
		entity.credentialPrefix = 'Net' + netId + '.' + capitalizeFirstLetter(entity.name);
		entity.name = 'net' + netId + '.' + entity.name;
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
