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
 * Generator for credentials for Auth and entity
 * @author Hokeun Kim
 */

var fs = require('fs');
var readlineSync = require('readline-sync');
const execSync = require('child_process').execSync;

const MASTER_PASSWORD = readlineSync.questionNewPassword('Enter new password for Auth: ', {min: 4, mask: ''});
const CA_PASSWORD = MASTER_PASSWORD;
const AUTH_PASSWORD = MASTER_PASSWORD;

// basic directories
const EXAMPLES_DIR = process.cwd() + '/';
process.chdir('..');
const PROJ_ROOT_DIR = process.cwd() + '/';

const AUTH_CREDS_DIR= PROJ_ROOT_DIR + 'auth/credentials/';
const ENTITY_CREDS_DIR= PROJ_ROOT_DIR + 'entity/credentials/';
const AUTH_DATABASES_DIR= PROJ_ROOT_DIR + 'auth/databases/';

// generate CA credentials
process.chdir(AUTH_CREDS_DIR);
execSync('./generateCACredentials.sh ' + CA_PASSWORD);

// generate Auth credentials and directories
var graph = JSON.parse(fs.readFileSync(EXAMPLES_DIR + 'configs/default.graph'));
var authList = graph.authList;
for (var i = 0; i < authList.length; i++) {
	var auth = authList[i];
	var authHost = 'localhost';
	if (auth.host != null) {
		authHost = auth.host;
	}
	execSync('./generateExampleAuthCredentials.sh ' + auth.id + ' ' + authHost + ' ' + CA_PASSWORD + ' ' + AUTH_PASSWORD);
	var MY_CERTS_DIR = AUTH_DATABASES_DIR + 'auth' + auth.id + '/my_certs/';
	execSync('mkdir -p ' + MY_CERTS_DIR);
	execSync('mv certs/Auth' + auth.id + '*Cert.pem ' + MY_CERTS_DIR);
	
	var MY_KEYSTORES_DIR = AUTH_DATABASES_DIR + 'auth' + auth.id + '/my_keystores/';
	execSync('mkdir -p ' + MY_KEYSTORES_DIR);
	execSync('mv keystores/Auth' + auth.id + '*.pfx ' + MY_KEYSTORES_DIR);
	var CURRENT_AUTH_DB_DIR = AUTH_DATABASES_DIR + 'auth' + auth.id;
	execSync('mkdir -p ' + CURRENT_AUTH_DB_DIR + '/entity_certs/');
	execSync('mkdir -p ' + CURRENT_AUTH_DB_DIR + '/entity_keys/');
	execSync('mkdir -p ' + CURRENT_AUTH_DB_DIR + '/trusted_auth_certs/');
}

// exchange credentials for trusted Auths
var authTrusts = graph.authTrusts;
function copyAuthCerts(fromId, toId) {
	var prefix = 'cp ' + AUTH_DATABASES_DIR + "auth" + fromId + '/my_certs/Auth' + fromId;
	var suffix = 'Cert.pem ' + AUTH_DATABASES_DIR + 'auth' + toId + '/trusted_auth_certs';
	execSync(prefix + 'Internet' + suffix);
	execSync(prefix + 'Entity' + suffix);
}
for (var i = 0; i < authTrusts.length; i++) {
	var authTrust = authTrusts[i];
	copyAuthCerts(authTrust.id1, authTrust.id2);
	copyAuthCerts(authTrust.id2, authTrust.id1);
}

console.log(execSync('pwd').toString());

console.log(graph);