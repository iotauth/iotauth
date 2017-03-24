# Auth directory

This directory includes an open-source implementation of Auth, using the IntelliJ IDEA.
We strongly recommend looking into [*examples*](https://github.com/iotauth/iotauth/tree/master/examples) before setting up the environment, since this includes ways to locally generate your own credentials that will be used by Auth for actual execution of Auth.

# Directory structure
---
- **auth-server**: Directory for auth-server module
- **credentials**: Directory for certificates and keystores of Auth
- **databases**: Directory for SQLite database and entity/trusted Auth certificates
- **example-auth-db-generator**: Directory for example-auth-db-generato module
- **jars**: Directory for storing external jar files
- **library**: Directory for library module (on which *auth-server* and *example-auth-db-generator* depend)
- **properties**: Properties files for auth server

# Using IntelliJ IDEA
---
Install IntelliJ IDEA https://www.jetbrains.com/idea/.
For the following instructions, we use $ROOT to indicate the root directory of this repository.

* First, open project ($Root/auth) from IntelliJ IDEA

* To import Maven dependencies,
  * Right click on pom.xml
  * Select Maven -> Reimport

* To enable Maven projects auto-import,
  * On menu, click on
    * File | Other Settings | Default Settings
  * In the pop-up window, select 
    * Build, Execution, Deployment -> Build Tools -> Maven -> Importing
  * Check
    * Import Maven projects automatically

* To build jar
  * In maven project tab, inside auth-server -> lifecycle 
  * Select from clean to install and run (click on the green triangle at the top of Maven Project tab)

* To run jar file
  * See the [this](https://github.com/iotauth/iotauth/blob/master/auth/auth-server/README.md) (the README file of auth-server module.)

* To generate JavaDoc
  * In IntelliJ IDEA, Tools -> Generate JavaDoc, set output directory $ROOT/auth/doc and click OK. The directory will be created automatically.

* Run -> Run/Debug configurations
  * Check "single instance only"
  
* To configure run/debug configurations for example Auths,

![Image of Auth101 Config](https://raw.githubusercontent.com/iotauth/iotauth/master/examples/figures/auth101_intellij_config.png)

![Image of Auth102 Config](https://raw.githubusercontent.com/iotauth/iotauth/master/examples/figures/auth102_intellij_config.png)
