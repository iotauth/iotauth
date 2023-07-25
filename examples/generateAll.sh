#!/bin/bash

# Author: Hokeun Kim
# Script for generating example Auths and entities

echo "*SCRIPT- generateAll.sh: For generating example Auths and entities"

# followings are default parameters
# file for host and port assignment of Auth and entities
GRAPH_FILE="configs/default.graph"
# Whether to show help
SHOW_HELP=false
# Generate credentials and configs
GEN_CRED_CONFIG=true
# Generate Auth databases
GEN_AUTH_DB=true
# Remove files after DB generation
REMOVE_FILES_AFTER_DB_GEN=true

# parsing command line arguments
# -n for number of nets, -d for DB protection method and -a for host port assignment
while [[ $# -gt 0 ]]
do
	key="$1"

	case $key in
		-g|--graph)
			GRAPH_FILE="$2"
			shift # past argument
		;;
		-gc|--gen-cred-config-only)
			GEN_AUTH_DB=false
		;;
		-gd|--gen-db-only)
			GEN_CRED_CONFIG=false
		;;
		-lc|--leave-cred-config)
			REMOVE_FILES_AFTER_DB_GEN=false
		;;
		-p|--password)
			PASSWORD_FOR_CRED_GENERATION="$2"
			shift # past argument
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
	echo "  -g,--graph <arg>                Path for host and port assignment file."
	echo "  -gc,--gen-cred-config-only      Generate credentials and configuration files only."
	echo "                                  (without generating Auth DBs.)"
	echo "  -gd,--gen-db-only               Generate Auth databases only."
	echo "                                  (Skip generation of credentials and configuration files.)"
	echo "  -lc,--leave-cred-config         Leave credentials and config files after DB generation."
	echo "  -p|--password                   Password passed for credential generation."
	echo "                                  (Must not be used for actual deployment.)"
	echo "  -h,--help                       Show this help."
	exit 1
fi

echo "Example generation options:"
echo GRAPH_FILE  = $GRAPH_FILE

# if required npm modules do not exist
if [ ! -d "node_modules/readline-sync" ] ||  [ ! -d "node_modules/JSON2" ]; then
	echo "Installing required npm modules for generating configuration ..."
	./initConfigs.sh
fi

# Initialize Node.js example entities (npm installation)
EXAMPLES_DIR=`eval pwd`
cd ../entity/node
echo "Installing required npm modules for example node entities ..."
./initNodeEntities.sh
cd $EXAMPLES_DIR

# generate credentials and configs
if [ "$GEN_CRED_CONFIG" = true ] ; then
	echo "Generating credentials ..."
	node credentialGenerator.js $GRAPH_FILE $PASSWORD_FOR_CRED_GENERATION
	if [ $? -ne 0  ] ; then
		echo "[Error] Script finished with problems! exiting..." ; exit 1
	fi
	echo "Generating entity configuration files..."
	node entityConfigGenerator.js $GRAPH_FILE
	if [ $? -ne 0  ] ; then
		echo "[Error] Script finished with problems! exiting..." ; exit 1
	fi
	echo "Generating Auth configuration files..."
	node authConfigGenerator.js $GRAPH_FILE
	if [ $? -ne 0  ] ; then
		echo "[Error] Script finished with problems! exiting..." ; exit 1
	fi
fi

if [ "$GEN_AUTH_DB" = true ] ; then
	echo "Generating auth databases..."
	# generate Auth DBs
	node authDBGenerator.js $GRAPH_FILE $REMOVE_FILES_AFTER_DB_GEN
	if [ $? -ne 0  ] ; then
		echo "[Error] Script finished with problems! exiting..." ; exit 1
	fi
fi
