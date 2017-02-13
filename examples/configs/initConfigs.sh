#!/bin/bash

# This script is for initializing config files for example Node.js entities
# Author: Hokeun Kim

# install required npm packages for config file generator in Node.js
npm install

if [ $# != 1 ]
then
	echo "Please provide required argument (number of networks)"
	echo 'Usage: ./initConfigs.sh NUM_NETS'
	exit
fi
# number of networks (Auths)
NUM_NETS=$1

cd ../..
node examples/configs/configGenenerator.js $NUM_NETS
