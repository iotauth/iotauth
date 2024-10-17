# Auth directory

This directory includes an open-source implementation of Auth, using the IntelliJ IDEA.
We strongly recommend looking into [*examples*](https://github.com/iotauth/iotauth/tree/master/examples) before setting up the environment, since this includes ways to locally generate your own credentials that will be used by Auth for actual execution of Auth.

# Directory structure
---
- **auth-server**: Directory for auth-server module
- **credentials**: Directory for certificates and keystores of Auth
- **databases**: Directory for SQLite database and entity/trusted Auth certificates
- **example-auth-db-generator**: Directory for example-auth-db-generator module
- **jars**: Directory for storing external jar files
- **library**: Directory for library module (on which *auth-server* and *example-auth-db-generator* depend)
- **properties**: Properties files for auth server

# Using IntelliJ IDEA
---
Install IntelliJ IDEA https://www.jetbrains.com/idea/.
For the following instructions, we use $ROOT to indicate the root directory of this repository.

* First, open project ($Root/auth) from IntelliJ IDEA

* To configure JDK (When you get `No JDK specified` error)
  * Select File -> Project Structure.
  * Choose SDK (e.g., openjdk-11 or openjdk-17)
  * Choose Language level (11 or above).

* To import Maven dependencies,
  * Right click on pom.xml
  * Select Maven -> Reload Project (or something similar)

* To enable Maven projects auto-import (*optional*),
  * On menu, click on
    * IntelliJ IDEA | Preferences
  * In the pop-up window, select 
    * Build, Execution, Deployment -> Build Tools -> Maven -> Importing
  * Check under `Automatically download`
    * Sources, Documentation, Annotations (whichever you prefer)

* To build jar
  * In maven project tab, inside auth-server -> lifecycle 
  * Select from clean to install and run (click on the green triangle at the top of Maven Project tab)

* To run jar file
  * See the [this](https://github.com/iotauth/iotauth/blob/master/auth/auth-server/README.md) (the README file of auth-server module.)

* To generate JavaDoc
  * In menu bar, select Tools -> Generate JavaDoc, set output directory $ROOT/auth/doc and click OK. The directory will be created automatically.

* Run -> Run/Debug configurations
  * Check "single instance only"
  
* To configure run/debug configurations for example Auths,
  * Properties
    * `-p ../properties/exampleAuth101.properties`
    * `-p ../properties/exampleAuth102.properties`

![Image of Auth101 Config](https://raw.githubusercontent.com/iotauth/iotauth/master/examples/figures/auth101_intellij_config.png)

![Image of Auth102 Config](https://raw.githubusercontent.com/iotauth/iotauth/master/examples/figures/auth102_intellij_config.png)


# Using VSCode

* Install the [Maven for Java](https://marketplace.visualstudio.com/items?itemName=vscjava.vscode-maven) and [Extension Pack for Java](https://marketplace.visualstudio.com/items?itemName=vscjava.vscode-java-pack) extensions.

* Get to the `Explorer` (Ctrl+Shift+E), and find the `Maven` tab. Go to the `auth-server/Lifecycle`, and push the play button on `clean` and `install`.

* Add the below configuration to `launch.json`.
```
        {
            "name": "auth",
            "type": "java",
            "request": "launch",
            "mainClass": "org.iot.auth.AuthServer",
            "args": [
                "-p",
                "../properties/exampleAuth101.properties"
            ],
            "cwd": "${workspaceFolder}/auth/auth-server",
            "vmArgs": "-Djava.version=17",
            "javaHome": "/usr/lib/jvm/java-17-openjdk-amd64/bin/java"
        },
```

* Also, add `"java.jdt.ls.java.home": "/usr/lib/jvm/java-17-openjdk-amd64/bin/java"` to `settings.json`.
* Then, push the `F5`.