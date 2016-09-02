#!/bin/bash

echo `pwd`
if [ ! -d "../databases/auth101" ];
then
    echo "need to create databases"
else
	cd ../
	mvn -pl example-auth-db-generator -am install
	cd example-auth-db-generator
    cp target/init-example-auth-db-jar-with-dependencies.jar ../
    cd ../
    java -jar init-example-auth-db-jar-with-dependencies.jar
    rm init-example-auth-db-jar-with-dependencies.jar
fi