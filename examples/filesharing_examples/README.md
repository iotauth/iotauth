# Overview
---
This directory includes descryptions for fileshairng and DataManagementEntity.py that manages sessionkeyid, file hash value, purpose for filesharing.


# Example details
---
![Image of Example for Filesharing](https://raw.githubusercontent.com/iotauth/iotauth/ipfs/examples/filesharing_examples/figures/example_description.png)

The figure above illustrates the example with Auths (*Auth*), their example entities and data management entity. *Auth* is an authorization entity for network 1 (net1), and it has two registered entities, namely, *net1.uploader* and *net1.downloader*. Data management entity manages the information for files.

Auth provides the secure session key with net1.uploader and net1.downloader according to communication policy. If net1.uploader gets the session key from Auth, net1.uploader can encrypt the file with session key. Then, net1.uplodaer uploads the encrypted file to IPFS. IPFS is decentralized distributed file system and everyone can download the file using hash value. when net1.uploader uploads the file, net1.uploader transfer the data including file hash value, sessionkey id, and purpose to data management entity.

 net1.downloader requests the file information to data management entity. Data management entity confirms the net1.downloader and gives the file information. 
net1.downloader checks if there is a key that fits the session key ID, and if not, requests the session key from Auth. net1.downloader who received the session key from Auth downloads the encrypted file from IPFS and decrypts the file using the session key.

# Data Management Entity
Data management entity is an entity that manages detailed information about files registered in IPFS. When a file is uploaded to IPFS, the file appears only as a hash value, with no other information. However, when a person wants to give files only to certain people, he or she must use hash values and other information to block access to others. The way to block other people's access can be blocked if Auth does not provide a session key. However, another entity is required to obtain information on the session key. Therefore, Data management entity stores session keys and purposes according to hash values together to provide these information when a specific entity requests information.



# How to run examples
---
For this section, we use *$ROOT* for the root directory of this repository.

### To run IPFS (in command line)
1. Run 'ipfs daemon' to activate an IPFS environment. (IPFS command line tools should be installed a priori. If it is not installed, then you can install it easily by reading [IPFS install](https://docs.ipfs.tech/install/command-line/#install-official-binary-distributions)).

### To run example Auths (in command line)
See README.md under *examples/*.
### To run example data management entity
1. Run 'git submodule update --remote' to move the ipfs submodule for filesharing.

2. Change directories to *$ROOT/examples/filesharing_examples/*.

3. Run 'python3 DataManageEntity.py' to execute data management entity.

### To run example entities written in C language.
See README.md under *entity/c/*.
