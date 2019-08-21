#!/bin/bash

# Script for generating ILP solutions for different trust and Auth kill order.
# Author: Hokeun Kim

EXEC_CMD="java -jar target/migration-solver-jar-with-dependencies.jar"
TRUST_ID="trust3"
INPUT="data/cory45_trust3.json"

############################################################

ORDER_ID="order1"
AUTH_KILL_ORDER="504,402,501,403,503,401"

mkdir -p results/$TRUST_ID/$ORDER_ID
$EXEC_CMD -i $INPUT -d $AUTH_KILL_ORDER -o results/$TRUST_ID/$ORDER_ID/cory45_plan_ILP.json
$EXEC_CMD -i $INPUT -d $AUTH_KILL_ORDER -o results/$TRUST_ID/$ORDER_ID/cory45_plan_ILP_mt_ac.json -m -a

############################################################

ORDER_ID="order2"
AUTH_KILL_ORDER="501,403,504,401,503,402"

mkdir -p results/$TRUST_ID/$ORDER_ID
$EXEC_CMD -i $INPUT -d $AUTH_KILL_ORDER -o results/$TRUST_ID/$ORDER_ID/cory45_plan_ILP.json
$EXEC_CMD -i $INPUT -d $AUTH_KILL_ORDER -o results/$TRUST_ID/$ORDER_ID/cory45_plan_ILP_mt_ac.json -m -a

############################################################

ORDER_ID="order3"
AUTH_KILL_ORDER="503,504,402,403,401,501"

mkdir -p results/$TRUST_ID/$ORDER_ID
$EXEC_CMD -i $INPUT -d $AUTH_KILL_ORDER -o results/$TRUST_ID/$ORDER_ID/cory45_plan_ILP.json
$EXEC_CMD -i $INPUT -d $AUTH_KILL_ORDER -o results/$TRUST_ID/$ORDER_ID/cory45_plan_ILP_mt_ac.json -m -a

############################################################

ORDER_ID="order4"
AUTH_KILL_ORDER="402,503,504,401,501,403"

mkdir -p results/$TRUST_ID/$ORDER_ID
$EXEC_CMD -i $INPUT -d $AUTH_KILL_ORDER -o results/$TRUST_ID/$ORDER_ID/cory45_plan_ILP.json
$EXEC_CMD -i $INPUT -d $AUTH_KILL_ORDER -o results/$TRUST_ID/$ORDER_ID/cory45_plan_ILP_mt_ac.json -m -a

############################################################

ORDER_ID="order5"
AUTH_KILL_ORDER="504,501,503,401,402,403"

mkdir -p results/$TRUST_ID/$ORDER_ID
$EXEC_CMD -i $INPUT -d $AUTH_KILL_ORDER -o results/$TRUST_ID/$ORDER_ID/cory45_plan_ILP.json
$EXEC_CMD -i $INPUT -d $AUTH_KILL_ORDER -o results/$TRUST_ID/$ORDER_ID/cory45_plan_ILP_mt_ac.json -m -a

############################################################

ORDER_ID="order6"
AUTH_KILL_ORDER="401,504,402,403,501,503"

mkdir -p results/$TRUST_ID/$ORDER_ID
$EXEC_CMD -i $INPUT -d $AUTH_KILL_ORDER -o results/$TRUST_ID/$ORDER_ID/cory45_plan_ILP.json
$EXEC_CMD -i $INPUT -d $AUTH_KILL_ORDER -o results/$TRUST_ID/$ORDER_ID/cory45_plan_ILP_mt_ac.json -m -a

############################################################
