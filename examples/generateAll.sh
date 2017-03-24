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
# file for auth DB configuration
AUTH_DB_CONFIG_FILE="configs/defaultAuthDB.config"
# Whether to show help
SHOW_HELP=false
# Generate credentials and configs
GEN_CRED_CONFIG=true
# Generate Auth databases
GEN_AUTH_DB=true

# parsing command line arguments
# -n for number of nets, -d for DB protection method and -a for host port assignment
while [[ $# -gt 0 ]]
do
	key="$1"

	case $key in
		-n|--num-nets)
			NUM_NETS="$2"
			shift # past argument
		;;
		-d|--db-protect)
			AUTH_DB_PROTECTION_METHOD="$2"
			shift # past argument
		;;
		-a|--host-port-assign)
			HOST_PORT_ASSIGNMENT_FILE="$2"
			shift # past argument
		;;
		-c|--auth-db-config)
			AUTH_DB_CONFIG_FILE="$2"
			shift # past argument
		;;
		-gc|--gen-cred-config-only)
			GEN_AUTH_DB=false
		;;
		-gd|--gen-db-only)
			GEN_CRED_CONFIG=false
		;;
		-h|--help)
			SHOW_HELP=true
		;;
		*)
			# unknown option
		;;
	esac
	shift # past argument or value
done

if [ "$SHOW_HELP" = true ] ; then
	echo "Usage: ./generateAll.sh [options]"
	echo
	echo "Options:"
	echo "  -n,--num-nets <arg>             Number of networks (Auths). Default value is 2."
	echo "  -d,--db-protect <arg>           Auth DB protection method [0-2]. Default value is 1."
	echo "                                  [0: No encryption, 1: Encrypt credentials, 2: Encrypt entire DB]"
	echo "  -a,--host-port-assign <arg>     Path for host and port assignment file."
	echo "  -c,--auth-db-config <arg>       Path for Auth DB configuration file."
	echo "  -gc,--gen-cred-config-only      Generate credentials and configuration files only."
	echo "                                  (without generating Auth DBs.)"
	echo "  -gd,--gen-db-only               Generate Auth databases only."
	echo "                                  (Skip generation of credentials and configuration files.)"
	echo "  -h,--help                       Show this help."
	exit
fi

echo "Example generation options:"
echo NUM_NETS                   = $NUM_NETS
echo AUTH_DB_PROTECTION_METHOD  = $AUTH_DB_PROTECTION_METHOD
echo HOST_PORT_ASSIGNMENT_FILE  = $HOST_PORT_ASSIGNMENT_FILE
echo AUTH_DB_CONFIG_FILE        = $AUTH_DB_CONFIG_FILE

# generate credentials and configs
if [ "$GEN_CRED_CONFIG" = true ] ; then
	echo "Generating credentials and configuration files..."
	./generateCredentialsAndConfigs.sh $NUM_NETS $AUTH_DB_PROTECTION_METHOD $AUTH_DB_CONFIG_FILE $HOST_PORT_ASSIGNMENT_FILE
fi

if [ "$GEN_AUTH_DB" = true ] ; then
	echo "Generating auth databases..."
	# generate Auth DBs
	./generateDB.sh $NUM_NETS $AUTH_DB_PROTECTION_METHOD
fi
