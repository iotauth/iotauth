#!/bin/bash

SESSION_KEY_JAVA_FILE=app/src/main/java/org/iot/auth/crypto/SessionKey.java
CACHED_SESSION_KEY_TABLE_JAVA_FILE=app/src/main/java/org/iot/auth/db/bean/CachedSessionKeyTable.java
TEMP_FILE=temp20170306.txt

cp -r ../auth/library/src/main/java/org/iot/auth/* app/src/main/java/org/iot/auth/


# To replace String.join with android.text.TextUtils.join

sed 's/String.join/android.text.TextUtils.join/g' $SESSION_KEY_JAVA_FILE > $TEMP_FILE
mv $TEMP_FILE $SESSION_KEY_JAVA_FILE

sed 's/String.join/android.text.TextUtils.join/g' $CACHED_SESSION_KEY_TABLE_JAVA_FILE > $TEMP_FILE
mv $TEMP_FILE $CACHED_SESSION_KEY_TABLE_JAVA_FILE

##
