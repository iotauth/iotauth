# To re-generate default graphs

* For help

	node defaultGraphGenerator.js --help

* For generating **default.graph**

	node defaultGraphGenerator.js -c

* For generating **default_three_auths.graph**

	node defaultGraphGenerator.js -b -n 3 -o default_three_auths.graph

* For generating **default_three_auths_backup_to_all.graph**

	node defaultGraphGenerator.js -b -a -n 3 -o default_three_auths_backup_to_all.graph
	
* For generating **file_sharing.graph**

	node defaultGraphGenerator.js -f -o file_sharing.graph

## Graph types

* `default.graph`

	Default example SST topology containing two Auths (`Auth101` and `Auth102`) and their registered client/server entities across two separate networks (`net1` and `net2`).

* `privilege.graph`

	Multi-level delegated-access example topology used for automated privilege grand and revoke workflows.
  * Example entities include:
    * `Node0` ~ `Node6`
    * `ResourceA`, `ResourceB`, `ResourceC`, `ResourceD`
  * This graph is used together with `autoPrivilege.js` under [`entity/node/example_entities`](../../entity/node/example_entities).
  * Generate with 
    ```
    node defaultGraphGenerator.js -p -o privilege.graph
    ```
