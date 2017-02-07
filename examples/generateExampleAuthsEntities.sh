#!/bin/bash

# Script for generating example Auths and entities
# Author: Hokeun Kim

AUTH_CREDS_DIR=auth/credentials/
ENTITY_CREDS_DIR=entity/credentials/
AUTH_DATABASES_DIR=auth/databases/

read -s -p "Enter new password for Auth: " MASTER_PASSWORD

CA_PASSWORD=$MASTER_PASSWORD
AUTH_PASSWORD=$MASTER_PASSWORD

# Move to Auth credentials
cd ../
cd $AUTH_CREDS_DIR

# Generate CA credentials (with password asdf)
./generateCACredentials.sh $CA_PASSWORD

# Generate Auth credentials (with password asdf)
./generateExampleAuthCredentials.sh 101 localhost $CA_PASSWORD $AUTH_PASSWORD
./generateExampleAuthCredentials.sh 102 localhost $CA_PASSWORD $AUTH_PASSWORD

# Move to Entity credentials
cd ../../
cd $ENTITY_CREDS_DIR

# Generate Entity credentials
./generateExampleEntityCredentials.sh $CA_PASSWORD

# Move to repository root
cd ../../

# Copy Entity certificates to Auth databases
mkdir -p $AUTH_DATABASES_DIR/auth101/certs/
mkdir -p $AUTH_DATABASES_DIR/auth102/certs/

cp $ENTITY_CREDS_DIR/certs/net1/*.pem $AUTH_DATABASES_DIR/auth101/certs/
cp $ENTITY_CREDS_DIR/certs/net2/*.pem $AUTH_DATABASES_DIR/auth102/certs/

# Copy Auth certificates to Entity local directories
mkdir -p entity/auth_certs
cp $AUTH_CREDS_DIR/certs/*EntityCert.pem entity/auth_certs

# Initialize Node.js example entities (npm installation and config file generation)
cd entity/node
./initNodeEntities.sh
cd ../..

# Create example databases for Auths
cd auth/example-auth-db-generator
./generateExampleAuthDB.sh
cd ../..