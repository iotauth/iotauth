#!/bin/bash

# Author: Hokeun Kim
# Script for generating DB of example Auths based on generated credentials and configurations

echo "*SCRIPT- generateDB.sh: For generating DB of example Auths based on generated credentials and configurations"

AUTH_DATABASES_DIR=auth/databases/

if [ $# != 2 ]
then
	echo "Please provide required arguments (number of networks, Auth DB protection method)"
	echo 'Usage: ./generateDB.sh NUM_NETS AUTH_DB_PROTECTION_METHOD'
	exit
fi

# number of networks (Auths)
NUM_NETS=$1
# Protection method for Auth DB, see AuthDBProtectionMethod.java for supported methods
AUTH_DB_PROTECTION_METHOD=$2

# Whether to remove unnecessary key, cert, config files to be removed after DB generation
REMOVE_KEY_CERT_FILES=true
REMOVE_CONFIG_FILES=true

# Create example databases for Auths
cd ../auth/example-auth-db-generator
./generateExampleAuthDB.sh $NUM_NETS $AUTH_DB_PROTECTION_METHOD
cd ../..

net_id=1
while [ "$net_id" -le $NUM_NETS ]
do
	CURRENT_AUTH_DB_DIR=$AUTH_DATABASES_DIR"/auth10"$net_id
	if $REMOVE_KEY_CERT_FILES; then
		rm -rf $CURRENT_AUTH_DB_DIR"/my_certs/"
		rm -rf $CURRENT_AUTH_DB_DIR"/entity_certs/"
		rm -rf $CURRENT_AUTH_DB_DIR"/entity_keys/"
		rm -rf $CURRENT_AUTH_DB_DIR"/trusted_auth_certs/"
	fi
	if $REMOVE_CONFIG_FILES; then
		rm -rf $CURRENT_AUTH_DB_DIR"/configs/"
	fi
	let "net_id+=1"
done

