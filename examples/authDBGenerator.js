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
 * Generator DB for Auths
 * @author Hokeun Kim
 */

"use strict";

var fs = require('fs');
const execSync = require('child_process').execSync;

// get graph file
if (process.argv.length <= 2) {
    console.error('Graph file must be provided!');
    process.exit(1);
}
var graphFile = process.argv[2];
var graph = JSON.parse(fs.readFileSync(graphFile));

// basic directories
const EXAMPLES_DIR = process.cwd() + '/';

process.chdir('../auth/');
execSync('mvn -pl example-auth-db-generator -am install -DskipTests', {stdio: 'inherit'});
process.chdir('example-auth-db-generator');
execSync('cp target/init-example-auth-db-jar-with-dependencies.jar ../');
process.chdir('..');

var authList = graph.authList;

for (var i = 0; i < authList.length; i++) {
	var auth = authList[i];
	execSync('java -jar init-example-auth-db-jar-with-dependencies.jar -i ' + auth.id + ' -d ' + auth.dbProtectionMethod);
}
execSync('rm init-example-auth-db-jar-with-dependencies.jar');
