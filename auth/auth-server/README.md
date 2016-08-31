# Overview
---
This is a directory for auth-server module.

# How to run Auth
---

2. While in this directory, run 'mvn clean install' to build an executable jar file. (Maven command line tools should be installed a priori. If it is not installed and you are using Mac OS X, then you can install it easily using [Homebrew](http://brew.sh/), by entering 'brew install maven'.)

3. Run the jar file with 'java -jar target/auth-server-jar-with-dependencies.jar -p **$PROPERTIES_FILE_PATH**'. Specify your own properties file for the Auth (example Auth properties files are provided in the directory *$ROOT/auth/properties*). Information of the Auth that you are running will appear on the screen. If you see 'Enter command (e.g., show re/cp/ta/sk, clean sk):' at the end of the screen, that means the Auth is successfully running.
