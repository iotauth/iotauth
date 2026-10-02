#!/bin/bash

# Test script for generating and inspecting physical presence configuration in auth.db
echo "============================================================"
echo " Running Physical Presence DB Generation & Test..."
echo "============================================================"

# 1. Clean existing databases and configs
./cleanAll.sh

# 2. Generate DB with physical_presence graph, policies, and challenges
./generateAll.sh \
  --graph configs/physical_presence.graph \
  --policy policies/physical_presence.json \
  --challenges physical_context_challenges/challenges.json \
  --password testpassword \
  --leave-cred-config

if [ $? -ne 0 ]; then
  echo "[ERROR] Database generation failed."
  exit 1
fi

echo ""
echo "============================================================"
echo " Inspecting generated auth.db for Auth 101..."
echo "============================================================"

DB_PATH="../auth/databases/auth101/auth.db"

if [ ! -f "$DB_PATH" ]; then
  echo "[ERROR] Database file $DB_PATH not found."
  exit 1
fi

echo ""
echo "--- 1. Registered Entities (Resources Capabilities) ---"
sqlite3 "$DB_PATH" "SELECT Name, [Group], Resources FROM registered_entity;"

echo ""
echo "--- 2. Communication Policies (Challenges Requirements) ---"
sqlite3 "$DB_PATH" "SELECT ID, RequestingGroup, Target, Context FROM communication_policy;"

echo ""
echo "--- 3. Physical Challenge Definitions (Topology & Methods) ---"
sqlite3 "$DB_PATH" "SELECT CheckID, Topology, Methods FROM physical_challenge;"

echo ""
echo "--- 4. MetaDataTable PhysicalChallengeDefinitions ---"
sqlite3 "$DB_PATH" "SELECT Key, Value FROM meta_data WHERE Key='PhysicalChallengeDefinitions';"

echo ""
echo "============================================================"
echo " SUCCESS: All configurations loaded successfully into auth.db!"
echo "============================================================"
