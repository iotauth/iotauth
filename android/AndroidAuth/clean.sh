#!/bin/bash

# A script for cleaning Java source codes from auth directory.
# Author: Hokeun Kim

cd app/src/main/java/org/iot/auth/
rm -rf config crypto db exception io message server util
rm AuthServer.java AuthCommandLine.java
