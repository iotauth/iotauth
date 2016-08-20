# Auth directory

This directory includes an open-source implementation of Auth, using IntelliJ IDEA

# Directory structure
---
- **credentials**: Directory for certificates and keystores of Auth
- **databases**: Directory for SQLite database and entity/trusted Auth certificates
- **src**: Directory for source codes and resources
    - **main**: Main source codes for auth server
        - **java**: Java source code
        - **resources**: Properties file for auth server
    - **test**: Source codes for unit tests
- **test-unit**: Directory for Java code for generating example Auth databases

# Using IntelliJ IDEA
---
Install IntelliJ IDEA https://www.jetbrains.com/idea/

Open project from IntelliJ IDEA

Run -> Run/Debug configurations
- Check "single instance only"

To import Maven dependencies,
- Right click on pom.xml
- Select Maven -> Reimport

To enable Maven projects auto-import,
- On menu, click on
-- File | Other Settings | Default Settings
- In the pop-up window, select 
-- Build, Execution, Deployment -> Build Tools -> Maven -> Importing
- Check
-- Import Maven projects automatically

To generate example Auth databases
- Use src/test/java/org/iot/auth/test/GenExampleAuthDB.java

To initialize example with auth101 and auth102
- go into scripts
- run ./genExampleAuthsEntities.sh
- run the test GenExampleAuthDB (in test-unit/src/main/java/org/iot/auth/test/GenExampleAuthDB.java)

To remove example
- run ./cleanExampleAuthsEntities.sh

To build jar
- In maven project tab, inside auth-server -> lifecycle 
- select from clean to install and run (click on the green triangle at the top of Maven Project tab)

To run jar file
- java -jar target/auth-server-0.0.1-jar-with-dependencies.jar -p authServer2.properties

To generate Javadoc
- in IntelliJ IDEA, Tools -> Generate JavaDoc, set output directory (e.g., auth/target/doc) and click OK