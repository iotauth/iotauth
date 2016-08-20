#!/bin/bash

echo `pwd`
if [ ! -d "../databases/auth101" ];
then
    echo "need to create databases"
else
    mvn clean install
    cp target/init-example-auth-db-jar-with-dependencies.jar ../
    cd ../
    java -jar init-example-auth-db-jar-with-dependencies.jar
    rm init-example-auth-db-jar-with-dependencies.jar
fi