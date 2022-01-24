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

"use strict";

var fs = require('fs');
// Ending with Sync will not return until the child process terminates.
var readlineSync = require('readline-sync');
const execSync = require('child_process').execSync;
const execFileSync = require('child_process').execFileSync;
// Use spawnSync instead of execSync or execFileSync for the commands
// involving asterisks (*) to be expanded in shell. openssl commands
// seem to require spawnSync and some of them also require {shell: true}.
var spawnSync = require('child_process').spawnSync; 

// get graph file
if (process.argv.length <= 2) {
    console.error('Graph file must be provided!');
    process.exit(1);
}
var graphFile = process.argv[2];
var graph = JSON.parse(fs.readFileSync(graphFile));

const EXAMPLES_DIR = process.cwd() + '/';

// Check if password is given as a command line argument.
var cmdLineGivenPassword = ''
if (process.argv.length > 3) {
    cmdLineGivenPassword = process.argv[3];
}
if (cmdLineGivenPassword.length > 0) {
    // If password is given as a command line argument.
    console.log('Password is given as a command line argument!');
    console.warn('Passing password as a command line argument is NOT secure!');
    console.warn('This should be only for automated experiments, NOT for deployment!');
    inputPassword = cmdLineGivenPassword;
}
else {
    // Otherwise, receive password through interactive dialogue.
    var inputPassword = readlineSync.question('Enter new password for Auth: ', {hideEchoBack: true, mask: ''});
    var repeatPassword = readlineSync.question('Enter the same password again: ', {hideEchoBack: true, mask: ''});
    if (inputPassword !== repeatPassword) {
        console.error('Passwords do not match!');
        process.exit(1);
    }
    if (inputPassword.length < 4) {
        console.error('Password must be at least four characters!');
        process.exit(1);
    }
}
//const MASTER_PASSWORD = readlineSync.questionNewPassword('Enter new password for Auth: ', {min: 4, mask: ''});
const MASTER_PASSWORD = inputPassword;
const CA_PASSWORD = MASTER_PASSWORD;
const AUTH_PASSWORD = MASTER_PASSWORD;

// basic directories
process.chdir('..');
const PROJ_ROOT_DIR = process.cwd() + '/';

const AUTH_CREDS_DIR = PROJ_ROOT_DIR + 'auth/credentials/';
const CA_DIR = AUTH_CREDS_DIR + 'ca/';
const AUTH_DATABASES_DIR = PROJ_ROOT_DIR + 'auth/databases/';
const VAL_DAYS = 730;

// generate CA credentials
process.chdir(AUTH_CREDS_DIR);
execFileSync('./generateCACredentials.sh', [CA_PASSWORD]);

// generate Auth credentials and directories
var authList = graph.authList;
for (var i = 0; i < authList.length; i++) {
	var auth = authList[i];
	execFileSync('./generateExampleAuthCredentials.sh', [auth.id, auth.authHost, CA_PASSWORD, AUTH_PASSWORD]);
	var MY_CERTS_DIR = AUTH_DATABASES_DIR + 'auth' + auth.id + '/my_certs/';
	execFileSync('mkdir', ['-p', MY_CERTS_DIR]);
	spawnSync('mv', ['certs/Auth' + auth.id + '*Cert.pem', MY_CERTS_DIR], {shell: true});
	
	var MY_KEYSTORES_DIR = AUTH_DATABASES_DIR + 'auth' + auth.id + '/my_keystores/';
	execFileSync('mkdir', ['-p', MY_KEYSTORES_DIR]);
	spawnSync('mv', ['keystores/Auth' + auth.id + '*.pfx', MY_KEYSTORES_DIR], {shell: true});
	var CURRENT_AUTH_DB_DIR = AUTH_DATABASES_DIR + 'auth' + auth.id;
	execFileSync('mkdir', ['-p', CURRENT_AUTH_DB_DIR + '/entity_certs/']);
	execFileSync('mkdir', ['-p', CURRENT_AUTH_DB_DIR + '/entity_keys/']);
	execFileSync('mkdir', ['-p', CURRENT_AUTH_DB_DIR + '/trusted_auth_certs/']);
}

// exchange credentials for trusted Auths
function copyAuthCerts(fromId, toId) {
	var srcFilePrefix = AUTH_DATABASES_DIR + "auth" + fromId + '/my_certs/Auth' + fromId;
	var srcFileSuffix = 'Cert.pem';
	var dstDir = AUTH_DATABASES_DIR + 'auth' + toId + '/trusted_auth_certs';
	execFileSync('cp', [srcFilePrefix + 'Internet' + srcFileSuffix, dstDir]);
	execFileSync('cp', [srcFilePrefix + 'Entity' + srcFileSuffix, dstDir]);
}
var authTrusts = graph.authTrusts;
for (var i = 0; i < authTrusts.length; i++) {
	var authTrust = authTrusts[i];
	copyAuthCerts(authTrust.id1, authTrust.id2);
	copyAuthCerts(authTrust.id2, authTrust.id1);
}

// copy Auth certs to entity directory
const AUTH_CERTS_DIR = PROJ_ROOT_DIR + 'entity/auth_certs';
execFileSync('mkdir', ['-p', AUTH_CERTS_DIR]);
spawnSync('cp', [AUTH_DATABASES_DIR + 'auth*/my_certs/*EntityCert.pem', AUTH_CERTS_DIR], {shell: true});

// generate entity credentials
function generateEntityCert(entity, copyTo, keyPathPrefix, certPathPrefix) {
	spawnSync('openssl', ['genrsa', '-out', keyPathPrefix + 'Key.pem 2048'], {shell: true});
	spawnSync('openssl', ['req', '-new', '-key', keyPathPrefix + 'Key.pem', '-sha256', '-out', keyPathPrefix + 'Req.pem',
		'-subj', '/C=US/ST=CA/L=Berkeley/O=EECS/OU=' + entity.netName + '/CN=' + entity.name]);
	spawnSync('openssl', ['x509', '-passin', 'pass:' + CA_PASSWORD, '-req', '-in', keyPathPrefix + 'Req.pem', '-sha256', '-extensions', 'usr_cert', '-CA',
		CA_DIR + 'CACert.pem', '-CAkey', CA_DIR + 'CAKey.pem', '-CAcreateserial', '-out', certPathPrefix + 'Cert.pem', '-days', VAL_DAYS]);
	execFileSync('rm', [keyPathPrefix + 'Req.pem']);
	if (entity.inDerFormat == true) {
		spawnSync('openssl', ['pkcs8', '-topk8', '-inform', 'PEM', '-outform', 'DER', '-in', keyPathPrefix + 'Key.pem', '-out', keyPathPrefix + 'Key.der', '-nocrypt']);
		execFileSync('rm', [keyPathPrefix + 'Key.pem']);
	}
	execFileSync('cp', [certPathPrefix + 'Cert.pem', copyTo]);
}
function generateEntityDistKey(entity, copyTo, keyPathPrefix) {
	const CIPHER_KEY_SIZE = 16;
	const MAC_KEY_SIZE = 32;
	spawnSync('openssl', ['rand', CIPHER_KEY_SIZE, '>', keyPathPrefix + 'CipherKey.key'], {shell: true});
	spawnSync('openssl', ['rand', MAC_KEY_SIZE, '>', keyPathPrefix + 'MacKey.key'], {shell: true});

	execFileSync('cp', [keyPathPrefix +'CipherKey.key', copyTo]);
	execFileSync('cp', [keyPathPrefix + 'MacKey.key', copyTo]);
}
function generateEntityCredential(entity, copyTo) {
	const ENTITY_CREDS_DIR = PROJ_ROOT_DIR + 'entity/credentials/';
	const ENTITY_CERTS_DIR = ENTITY_CREDS_DIR + 'certs/';
	const ENTITY_KEYS_DIR = ENTITY_CREDS_DIR + 'keys/';

	var KEYS_NET_DIR = ENTITY_KEYS_DIR + entity.netName + '/';
	execFileSync('mkdir', ['-p', KEYS_NET_DIR]);
	var keyPathPrefix = KEYS_NET_DIR + entity.credentialPrefix;
	if (entity.usePermanentDistKey == true) {
		generateEntityDistKey(entity, copyTo + 'entity_keys/', keyPathPrefix);
	}
	else {
		var CERTS_NET_DIR = ENTITY_CERTS_DIR + entity.netName + '/';
		execFileSync('mkdir', ['-p', CERTS_NET_DIR]);
		var certPathPrefix = CERTS_NET_DIR + entity.credentialPrefix;
		generateEntityCert(entity, copyTo + 'entity_certs/', keyPathPrefix, certPathPrefix);
	}
}
var entityList = graph.entityList;
var assignments = graph.assignments;
for (var i = 0; i < entityList.length; i++) {
	var entity = entityList[i];
	var authId = assignments[entity.name];
	generateEntityCredential(entity, AUTH_DATABASES_DIR + 'auth' + authId + '/');
}

//console.log(execSync('pwd').toString());

//console.log(graph);
