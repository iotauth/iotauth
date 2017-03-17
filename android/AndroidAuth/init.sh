#!/bin/bash

# A script for copying Java source codes from auth directory to port them to Android platform.
# Author: Hokeun Kim

# Temp file name for sed command
TEMP_FILE=temp20170306.txt

cp -r ../../auth/library/src/main/java/org/iot/auth/* app/src/main/java/org/iot/auth/
cp -r ../../auth/auth-server/src/main/java/org/iot/auth/* app/src/main/java/org/iot/auth/

# To replace String.join with android.text.TextUtils.join
SESSION_KEY_JAVA_FILE=app/src/main/java/org/iot/auth/crypto/SessionKey.java
CACHED_SESSION_KEY_TABLE_JAVA_FILE=app/src/main/java/org/iot/auth/db/bean/CachedSessionKeyTable.java

sed 's/String.join/android.text.TextUtils.join/g' $SESSION_KEY_JAVA_FILE > $TEMP_FILE
mv $TEMP_FILE $SESSION_KEY_JAVA_FILE

sed 's/String.join/android.text.TextUtils.join/g' $CACHED_SESSION_KEY_TABLE_JAVA_FILE > $TEMP_FILE
mv $TEMP_FILE $CACHED_SESSION_KEY_TABLE_JAVA_FILE
##

# To replace java.util.Base64 with android.util.Base64
BUFFER_KEY_JAVA_FILE=app/src/main/java/org/iot/auth/io/Buffer.java
sed 's/import java.util.Base64;/ /g; s/Base64.getEncoder().encodeToString(bytes)/android.util.Base64.encodeToString(bytes, android.util.Base64.DEFAULT)/g; s/Base64.getDecoder().decode(base64)/android.util.Base64.decode(base64, android.util.Base64.DEFAULT)/g' $BUFFER_KEY_JAVA_FILE > $TEMP_FILE
mv $TEMP_FILE $BUFFER_KEY_JAVA_FILE

# Remove unsupported features in some of imported Java source code files.
./importAuthServer.py
