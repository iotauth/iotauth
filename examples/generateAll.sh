#!/bin/bash

# Author: Hokeun Kim
# Script for generating example Auths and entities

echo "*SCRIPT- generateAll.sh: For generating example Auths and entities"

# followings are default parameters
# number of networks (Auths)
NUM_NETS=2
# Protection method for Auth DB, see AuthDBProtectionMethod.java for supported methods
AUTH_DB_PROTECTION_METHOD=1
# file for host and port assignment of Auth and entities
HOST_PORT_ASSIGNMENT_FILE=""

# parsing command line arguments
# -n for number of nets, -d for DB protection method and -a for host port assignment
while [[ $# -gt 1 ]]
do
	key="$1"

	case $key in
		-n|--numnets)
			NUM_NETS="$2"
			shift # past argument
		;;
		-d|--dbprotect)
			AUTH_DB_PROTECTION_METHOD="$2"
			shift # past argument
		;;
		-a|--hostportassign)
			HOST_PORT_ASSIGNMENT_FILE="$2"
			shift # past argument
		;;
		*)
			# unknown option
		;;
	esac
	shift # past argument or value
done

echo "Example generation options:"
echo NUM_NETS					= $NUM_NETS
echo AUTH_DB_PROTECTION_METHOD	= $AUTH_DB_PROTECTION_METHOD
echo HOST_PORT_ASSIGNMENT_FILE	= $HOST_PORT_ASSIGNMENT_FILE

# generate credentials and configs
./generateCredentialsAndConfigs.sh $NUM_NETS $AUTH_DB_PROTECTION_METHOD $HOST_PORT_ASSIGNMENT_FILE

# generate Auth DBs
./generateDB.sh $NUM_NETS $AUTH_DB_PROTECTION_METHOD

