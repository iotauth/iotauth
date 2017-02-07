#!/bin/bash

# Script for generating example Auths and entities
# Author: Hokeun Kim

AUTH_CREDS_DIR=auth/credentials/
ENTITY_CREDS_DIR=entity/credentials/
AUTH_DATABASES_DIR=auth/databases/
# number of networks (Auths)
NUM_NET=2

read -s -p "Enter new password for Auth: " MASTER_PASSWORD

CA_PASSWORD=$MASTER_PASSWORD
AUTH_PASSWORD=$MASTER_PASSWORD

# Move to Auth credentials
cd ../
cd $AUTH_CREDS_DIR

# Generate CA credentials
./generateCACredentials.sh $CA_PASSWORD

net_id=1
while [ "$net_id" -le $NUM_NET ]
do
	# Generate Auth credentials
	./generateExampleAuthCredentials.sh "10"$net_id localhost $CA_PASSWORD $AUTH_PASSWORD
	# Make directories for Entity certificates and keys for Auth databases
	mkdir -p ../../$AUTH_DATABASES_DIR"/auth10"$net_id"/entity_certs/"
	mkdir -p ../../$AUTH_DATABASES_DIR"/auth10"$net_id"/entity_keys/"
	let "net_id+=1"
done

# Move to repository root
cd ../../

# Move to Entity credentials
cd $ENTITY_CREDS_DIR

# Generate Entity credentials
./generateExampleEntityCredentials.sh $CA_PASSWORD

# Move to repository root
cd ../../

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