#!/bin/bash

# install required npm packages for example Node.js entities
npm install

# generate configuration files for example Node.js entities
cd example_entities/configs
node configGenenerator.js
cd ../..
