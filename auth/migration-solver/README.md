# The migration-solver module

This module contains the classes used to run the solver for migration plan optimization for better availability.
This module uses a jar file of [Gurobi optimizer](http://www.gurobi.com/).

# To get Gurobi jar files for academic use on Mac OS X
---
Request an academic license on Gurobi website ([http://www.gurobi.com/](http://www.gurobi.com/)),
and install the latest version of Gurobi.
The jar file can be found under "**/Library/gurobi801/mac64/lib**" by default.
Copy gurobi.jar to iotauth/auth/jars/gurobi/gurobi, to include 

**NOTE** *Do not commit gurobi.jar to the repository*, because Gurobi is a proprietary software. 

# How to build
---
* In command line

      cd $AUTH/../migration-solver
      mvn clean install

# How to run
---
* In command line

  * With a specified input file.

        java -jar target/migration-solver-jar-with-dependencies.jar -i data/cory5th.json

