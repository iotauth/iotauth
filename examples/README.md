# Overview
---
This directory includes scripts and descriptions for running example Auths and entities.
The scripts are used to clean and generate credentials (certificates and keystores) for example Auths and entities.

**Important: The examples described here are just for demonstration, not for actual deployment. Each Auth and each entity MUST be deployed separately in actual settings, although everything is assumed to be in the same machine in the following examples.**

# Example details
---
![Image of Example Auths and entities](https://raw.githubusercontent.com/iotauth/iotauth/master/examples/figures/example_description.png)

The figure above illustrates the example with two Auths (`Auth101` and `Auth102`) and their example entities. 
`Auth101` (Auth with ID 101) is an authorization entity for network 1 (net1), and it has two registered entities, namely, `net1.server` and `net1.client`. 
`Auth102` (Auth with ID 102) is for network 2 (net2) with two registered entities, `net2.server` and `net2.client`.

Each Auth has its own public keys (or certificates) and keystores in the directory, `auth/credentials/`. 
Each entity has its own public key and private key in the directory, `entity/credentials/`. 
These credentials (public keys and private keys) can be generated by running a script (generateExampleAuthsEntities.sh) included in this directory. 

Each Auth stores public keys of its registered entities, and each entity stores its Auth's public key. 
The script (generateExampleAuthsEntities.sh) also exchanges the public keys between each Auth and its entities by copying them. 
The Auths store the public keys of their entities as part of their databases, specifically, in the directories, `auth/databases/auth101/certs/` and `auth/databases/auth102/certs/`. 
For entities, the public keys of Auths are stored in the directory, `entity/auth_certs/`.

Database tables for storing authorization information should be initialized for each example Auth. 
The script (generateExampleAuthsEntities.sh) does this database initialization as the last step of the script. 
The initialized databases are created for `Auth101` and `Auth102` in the directorories, `auth/databases/auth101` and `auth/databases/auth101`, respectively, with the file name `auth.db`. 
Currently, we use SQLite for Auth databases.

# Script details
---
### generateAll.sh

This script takes as an input a `.graph` file (description of example Auths and entities,including network addresses, ports, Auth IDs, entity names, security configurations, and Auth-entity assignments) and generates credentials and configuration files for example Auths and entities.

- For detailed usages, use `./generateAll.sh --help`.

- The default graph files can be found in `examples/configs` and can be reconfigured and re-generated by a script `examples/configs/defaultGraphGenerator.js`. 
For more usage of this script, use ``node defaultGraphGenerator.js --help``.

Here are other Node.js script files that are internally used in `generateAll.sh`

- `examples/initConfigs.sh`: This initializes Node.js modules used by other Node.js scripts inside `generateAll.sh` (install required npm modules).

- `entity/node/initNodeEntities.sh`: Initializes Node.js example entities. This process includes Node.js npm installation.
  
- `examples/credentialGenerator.js`: This Node.js script first generates credentials (public/private key pairs and symmetric encryption keys) for example Auths and entities and places the credentials in specified local directories for Auths and entities. 
This script uses following helper scripts.

  - `auth/credentials/generateCACredentials.sh`: Generates credentials (public key, private key) for a certificate authority (CA) which signs certificates of example Auths and entities.

  - `auth/credentials/generateExampleAuthCredentials.sh`: Creates credentials for example Auths.

  - `entity/credentials/generateExampleEntityCredentials.sh`: Generates credentials for example entities.
  
- `examples/entityConfigGenerator.js`: This Node.js script creates configuration files for example entities. 
This script uses following helper script.
   
- `examples/authConfigGenerator.js`: This Node.js script creates configuration files and properties files for example Auths and entities.

- `examples/authDBGenerator.js`: This Node.js script compiles the DB generator program, `example-auth-db generator` (which is located in $ROOT/auth/example-auth-db-generator) and creates SQLite databases for Example Auths using the newly created credentials for Auths and entities.

### cleanAll.sh

This scripts deletes all credentials of example Auths and entities, and deletes databases for example Auths.

# How to run examples
---

For this section, we use `$ROOT` for the root directory of this repository.

### To generate credentials for example Auths and entities, and to create example Auth databases

1. Change directory to `$ROOT/examples`.

2. Run the script `generateAll.sh`, by entering `./generateAll.sh`. To run the script OpenSSL and Maven command line tools should be installed a priory. 
If you`re using Mac OS X, they can be installed using [Homebrew](http://brew.sh/), by entering `brew install openssl` and `brew install maven`.

3. You will be prompted to enter password for keystores of Auths. Enter you password to proceed.

4. If the script (generateExampleAuthsEntities.sh) finishes without an error, the credentials for Auths and entities and databases for Auths should be created. 
Here are instructions for running example Auths and entities.

5. If there is any error or you want to start with a clean copy, you can delete all generated credentials and Auth databases by running the script `cleanAll.sh`, with the command `./cleanAll.sh`.

### To run example Auths (in command line)

1. Change directories to `$ROOT/auth/auth-server/`.

2. Run `mvn clean install` to build an executable jar file. (Maven command line tools should be installed a priori. 
If it is not installed and you are using Mac OS X, then you can install it easily using [Homebrew](http://brew.sh/), by entering `brew install maven`.)

3. Run the jar file with the properties file for Auth101, with `java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties`. 
Information of Auth101 will appear on the screen. 
If you see `Enter command (e.g., show re/cp/ta/sk, clean sk):` at the end of the screen, that means Auth101 is successfully running.

4. For the example with multiple Auths, Run Auth102 with `java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth102.properties`, in a separate terminal.

5. After running example Auths, you can view database table contents of each Auth, using the show commands (show re, show cp, show ta, show sk).

### To run example Auths using IntelliJ IDEA for development.

See README.md under `auth/`.

### To run example entities written in Node.js

1. Change directories to `$ROOT/entity/node/example_entities/`.

2. Run `node client.js configs/net1/client.config`, to execute net1.client.

3. Run `node server.js configs/net1/server.config` in a separate terminal, to execute net1.server.

4. Within net1.client, enter `initComm net1.server` to start a secure communication with net1.server. 
This will trigger a session key request to Auth101 by net1.client, before net1.client connects to net1.server.

5. Within net1.client, enter `send blah blah` to send a (encrypted) message to net1.server, do the same within net1.server to send a (encrypted) message to net1.client.

6. Within net1.client, enter `finComm` to end the secure communication with net1.server.

7. For entities in net2 registered with Auth102, run `node client.js configs/net2/client.config`, to execute net2.client, and run `node server.js configs/net2/server.config`, to execute net2.server.

8. Do the same within net2.client and net2.server as in the steps 4-7.

### To run example entities written in C

1. Update `sst-c-api` submodule.
2. Change directories to `$ROOT/entity/c/examples/server_client_example`.

3. Build C examples.
```
$ mkdir build && cd build
$ cmake ../
$ make
```

4. Run `./entity_server ../c_server.config`, to execute net1.server.

4. Run `./entity_client ../c_client.config` in a separate terminal, to execute net1.client.

See https://github.com/iotauth/sst-c-api/tree/master/examples/ for more examples.

### To run example entities written in Cape Code

1. [Install Ptolemy II](https://icyphy.github.io/ptII/) and run the [Cape Code Swarmlet host](https://wiki.eecs.berkeley.edu/accessors/Main/CapeCodeHost). 
(For more information of Cape Code, see [here](https://chess.eecs.berkeley.edu/capecode/))

2. `$PTII` is for the root directory of the Ptolemy II repository. Open two Cape Code models, `$PTII/ptolemy/actor/lib/jjs/modules/iotAuth/demo/SecureCommClient/SecureCommClient.xml` and `$PTII/ptolemy/actor/lib/jjs/modules/iotAuth/demo/SecureCommServer/SecureCommServer.xml`.

3. Change the value of the parameter `IOTAUTH_HOME` of each Cape Code model to `$ROOT`.

4. Make sure Auth101 is running.

5. Run `SecureCommServer.xml` first then also run `SecureCommClient.xml`.

