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
 * Generator for experimental Auth entity graph
 * @author Hokeun Kim
 */

"use strict";

var fs = require('fs');
var JSON2 = require('JSON2');

var authList = [
	{id: 1},
	{id: 2},
	{id: 3}
];
var authTrusts = [
	{id1: 1, id2: 2},
	{id1: 1, id2: 3},
	{id1: 2, id2: 3}
];
var assignments = {
	't1': 1,
	't2': 1,
	't3': 2,
	't4': 2,
	't5': 3
}
// plan 2
var echoServerList = [
	{name: 't1', backupTo: 3},
	{name: 't3'}
];
var autoClientList = [
	{name: 't2', target: 't1', backupTo: 2},
	{name: 't4', target: 't3'},
	{name: 't5', target: 't1'}
];
var entityList = [];
var serverHostPortMap = {};

function populateAuthList() {
	var currentPort = 21100;
	for (var i = 0; i < authList.length; i++) {
		var auth = authList[i];
		authList[i] = {
			id: auth.id,
			entityHost: 'localhost',
			authHost: 'localhost',
			tcpPort: currentPort,
			udpPort: currentPort + 2,
			authPort: currentPort + 1,
			dbProtectionMethod: 1
		}
		currentPort += 100;
	}
}
function populateEchoServers() {
	var currentPort = 22100;
	for (var i = 0; i < echoServerList.length; i++) {
		var echoServer = echoServerList[i];
		var entity = {
			group: 'Servers',
			name: echoServer.name,
			host: 'localhost',
			port: currentPort,
			distProtocol: "TCP",
			usePermanentDistKey: false,
			distKeyValidityPeriod: "1*hour",
			maxSessionKeysPerRequest: 1,
			netName: 'Servers',
			credentialPrefix: echoServer.name + '.Server',
			backupToAuthId: echoServer.backupTo == null ? -1 : echoServer.backupTo
		}
		serverHostPortMap[entity.name] = {host: entity.host, port: entity.port};
		entityList.push(entity);
		currentPort++;
	}
}

function populateAutoClients() {
	for (var i = 0; i < autoClientList.length; i++) {
		var autoClient = autoClientList[i];
		var entity = {
			group: 'Clients',
			name: autoClient.name,
			distProtocol: 'TCP',
			usePermanentDistKey: false,
			distKeyValidityPeriod: '1*hour',
			maxSessionKeysPerRequest: 5,
			netName: 'Clients',
			credentialPrefix: autoClient.name + '.Client',
			backupToAuthId: autoClient.backupTo
		}
		var targetServerInfoList = [];
		if (autoClient.target != null) {
			var target = serverHostPortMap[autoClient.target];
			targetServerInfoList.push({
				name: autoClient.target,
				host: target.host,
				port: target.port
			})
		}
		if (targetServerInfoList.length > 0) {
			entity.targetServerInfoList = targetServerInfoList;
		}
		entityList.push(entity);
	}
}

// populate elements
populateAuthList();
populateEchoServers();
populateAutoClients();

var graph = {
	authList: authList,
	authTrusts: authTrusts,
	assignments: assignments,
	entityList: entityList
}

// write to file
fs.writeFileSync('exp.graph', 
	JSON2.stringify(graph, null, '\t'),
	'utf8'
);



