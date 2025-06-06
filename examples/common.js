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

const fs = require('fs');
const path = require('path');
// Use spawnSync instead of execSync or execFileSync for the commands
// involving asterisks (*) to be expanded in shell. openssl commands
// seem to require spawnSync and some of them also require {shell: true}.
var spawnSync = require('child_process').spawnSync; 

const execFileSync = require('child_process').execFileSync;

exports.DEFAULT_SIGN = 'RSA-SHA256';
exports.DEFAULT_RSA_KEY_SIZE = 256;     // 2048 bits
exports.DEFAULT_RSA_PADDING = 'RSA_PKCS1_PADDING';
exports.DEFAULT_CIPHER = 'AES-128-CBC';
exports.DEFAULT_MAC = 'SHA256';

// Copy file potentially including spaces.
exports.safeFileCopy = function(srcPath, dstDir) {
    const fileName = path.basename(srcPath);
	fs.copyFileSync(srcPath, path.join(dstDir, fileName));
}

// SpawnSync with error handling.
exports.safeSpawnSync = function(cmd, args) {
    const result = spawnSync(cmd, args, {shell: true});
    if (result.error) {
        // Execution failed (command not found or failed to execute).
        console.error('SpawnSync failed: ', result.error);
        throw new Error('safeSpawnSync failed!');
    } else if (result.status !== 0) {
        // Command ran but exited with non-zero exit code.
        console.error('SpawnSync failed with code:', result.status);
        console.error('Stderr:', result.stderr.toString());
        throw new Error('safeSpawnSync failed!');
    }
}
