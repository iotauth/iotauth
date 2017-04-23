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
var common = require('common');
const execSync = require('child_process').execSync;

const EXAMPLES_DIR = process.cwd() + '/';

// get graph file
var graphFile = 'configs/default.graph';
var graph = JSON.parse(fs.readFileSync(EXAMPLES_DIR + graphFile));

// basic directories
process.chdir('..');
const PROJ_ROOT_DIR = process.cwd() + '/';
const AUTH_DATABASES_DIR = PROJ_ROOT_DIR + 'auth/databases/';

function getAuthConfigDir(authId) {
	return AUTH_DATABASES_DIR + 'auth' + authId + '/configs/';
}
var authList = graph.authList;
function createConfigDirs() {
    for (var i = 0; i < authList.length; i++) {
    	var auth = authList[i];
        execSync('mkdir -p ' + getAuthConfigDir(auth.id));
    }
}

// generate registered entity table


// generate client policy table
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
		ID: auth.id, Host: auth.host, Port: auth.authPort,
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

// generate configs
createConfigDirs();
generateCommunicationPolicyTables();
generateTrustedAuthTables();
