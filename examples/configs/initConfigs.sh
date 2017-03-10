#!/bin/bash

# This script is for initializing config files for example Node.js entities
# Author: Hokeun Kim

# install required npm packages for config file generator in Node.js
npm install

if [ $# != 2 ]
then
	echo "Please provide required arguments (number of networks, Auth DB protection method)"
	echo 'Usage: ./initConfigs.sh NUM_NETS AUTH_DB_PROTECTION_METHOD'
	exit
fi
# number of networks (Auths)
NUM_NETS=$1
# Protection method for Auth DB, see AuthDBProtectionMethod.java for supported methods
AUTH_DB_PROTECTION_METHOD=$2

cd ../..
node examples/configs/configGenenerator.js $NUM_NETS $AUTH_DB_PROTECTION_METHOD

