#!/bin/bash

# This script is for initializing config files for example Node.js entities
# Author: Hokeun Kim

# install required npm packages for config file generator in Node.js
npm install

if [ $# -lt 3 ]
then
	echo "Please provide three required arguments (number of networks, Auth DB protection method, Auth DB configuration file)"
	echo 'Usage: ./initConfigs.sh NUM_NETS AUTH_DB_PROTECTION_METHOD AUTH_DB_CONFIG_FILE'
	exit
fi
# number of networks (Auths)
NUM_NETS=$1
# Protection method for Auth DB, see AuthDBProtectionMethod.java for supported methods
AUTH_DB_PROTECTION_METHOD=$2
# Auth DB configuration file
AUTH_DB_CONFIG_FILE="examples/"$3
# optional configuration for host port assignemt for network entities
if [ $# -ge 4 ]
then
	HOST_PORT_ASSIGNMENT_FILE="examples/"$4
fi

cd ../..
node examples/configs/configGenenerator.js $NUM_NETS $AUTH_DB_PROTECTION_METHOD $AUTH_DB_CONFIG_FILE $HOST_PORT_ASSIGNMENT_FILE

