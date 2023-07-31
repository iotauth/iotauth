# Overview
---
This directory includes descryptions for fileshairng and filesystem_manager.py that manages sessionkeyid, file hash value, purpose for filesharing.


# Example details
---
![Image of Example for Filesharing](https://raw.githubusercontent.com/iotauth/iotauth/ipfs/examples/filesharing_examples/figures/example_description.png)

The figure above illustrates the example with Auths (*Auth*), their example entities and filesystem manager. *Auth* is an authorization entity for network 1 (net1), and it has two registered entities, namely, *net1.uploader* and *net1.downloader*. Filesystem manager manages the information for files.

Auth provides the secure session key with net1.uploader and net1.downloader according to communication policy. If net1.uploader gets the session key from Auth, net1.uploader can encrypt the file with session key. Then, net1.uplodaer uploads the encrypted file to IPFS. IPFS is decentralized distributed file system and everyone can download the file using hash value. when net1.uploader uploads the file, net1.uploader transfer the data including file hash value, sessionkey id, and purpose to filesystem manager.

 net1.downloader requests the file information to filesystem manager. Filesystem manager confirms the net1.downloader and gives the file information. 
net1.downloader checks if there is a key that fits the session key ID, and if not, requests the session key from Auth. net1.downloader who received the session key from Auth downloads the encrypted file from IPFS and decrypts the file using the session key.

# Filesystem manager
Filesystem manager is an entity that manages detailed information about files registered in IPFS. When a file is uploaded to IPFS, the file appears only as a hash value, with no other information. However, when a person wants to give files only to certain people, he or she must use hash values and other information to block access to others. The way to block other people's access can be blocked if Auth does not provide a session key. However, another entity is required to obtain information on the session key. Therefore, Filesystem manager stores session keys and purposes according to hash values together to provide these information when a specific entity requests information. Details are below.

![Image of Example for Filesharing](https://raw.githubusercontent.com/iotauth/iotauth/ipfs/examples/filesharing_examples/figures/details_ for_filesystem_manager.png)



# How to run examples
---
For this section, we use *$ROOT* for the root directory of this repository.

### To generate credentials for example Auths and entities, and to create example Auth databases

1. Change directory to *$ROOT/examples*.

2. Run the script *generateAll.sh*, by entering './generateAll.sh -g configs/filesharing.graph'.

3. You will be prompted to enter password for keystores of Auths. Enter you password to proceed.

4. If there is any error or you want to start with a clean copy, you can delete all generated credentials and Auth databases by running the script *cleanAll.sh*, with the command './cleanAll.sh'.

### To run IPFS (in command line)
1. Run 'ipfs daemon' to activate an IPFS environment. (IPFS command line tools should be installed a priori. If it is not installed, then you can install it easily by reading [IPFS install](https://docs.ipfs.tech/install/command-line/#install-official-binary-distributions)).

### To run example Auths (in command line)
See README.md under *examples/* to know specific process.
1. Change directories $ROOT/auth/auth-server/.

2. Run 'mvn clean install' to build an executable jar file.

3. Run the jar file with the properties file for Auth101, with 'java -jar target/auth-server-jar-with-dependencies.jar -p ../properties/exampleAuth101.properties'.

4. Enter you password to proceed.

### To run example filesystem manager

1. Change directories to *$ROOT/examples/filesharing/*.

2. Run 'python3 filesystem_manager.py' to execute filesystem manager.

### To run example entities written in C language.
See README.md under *entity/c/* to know specific process.

1. Run 'git submodule update --remote' to move the ipfs submodule for filesharing.

2. Change directories to *$ROOT/entity/c/ipfs_examples/*

3. Run 'mkdir build && cd build'

4. Run 'cmake ../' to make the Makefile for build.

5. Run 'make' 

6. Run './entity_downloader ../downloader.config', to execute net1.downloader.

7. Run './entity_uploader ../uploader.config ../plain_text.txt' in a separate terminal, to execute net1.uploader.