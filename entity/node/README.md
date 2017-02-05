# Node directory
---
This directory includes entities written in [Node.js](https://nodejs.org/).

# Directory structure
---

- **data_examples**: Data examples used by node entities.

- **example_entities**: Various example entities written in Node.js.

# Required external packages ([npm](https://www.npmjs.com/))
---

The entities written in Node.js require external *npm* packages. These packages are specified in [package.json](https://github.com/iotauth/iotauth/blob/master/entity/node/package.json) that is included in this directory.

To install these *npm* packages locally, enter 'npm install' while in this directory (iotauth/entity/node/). The npm packages will be installed under the directory, *iotauth/entity/node/node_modules*.

- **mqtt**: For publisher and subscriber entities using the [MQTT message protocol](http://mqtt.org/).

- **sleep**: For testing time-outed entities.

- **JSON2**: For generation of configuration files for entities in a readable JSON format, used by [configGenenerator.js](https://github.com/iotauth/iotauth/blob/master/entity/node/example_entities/configs/configGenenerator.js) under iotauth/entity/node/example_entities/configs/.
