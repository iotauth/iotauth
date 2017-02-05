#!/bin/bash

# This script is for initializing Node.js example entities
# Author: Hokeun Kim

# install required npm packages for example Node.js entities
npm install

# generate configuration files for example Node.js entities
cd example_entities/configs
node configGenenerator.js
cd ../..
