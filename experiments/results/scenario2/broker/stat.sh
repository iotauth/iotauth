#!/bin/bash

FILE_NAME=$1
MQTT_LOCAL_PORT=$2
AUTH_CLIENT_PORT=$3
echo FILE_NAME: "$FILE_NAME", MQTT_LOCAL_PORT: "$MQTT_LOCAL_PORT", AUTH_CLIENT_PORT: "$AUTH_CLIENT_PORT"
echo sent packet count
tshark -2 -nr "$FILE_NAME" -R "tcp.srcport == $MQTT_LOCAL_PORT || tcp.srcport == $AUTH_CLIENT_PORT" -T fields -e frame.len | wc -l
echo sent packet total length
tshark -2 -nr "$FILE_NAME" -R "tcp.srcport == $MQTT_LOCAL_PORT || tcp.srcport == $AUTH_CLIENT_PORT" -T fields -e frame.len | awk '{sum+=$1}END{print sum}'
echo
echo received packet count
tshark -2 -nr "$FILE_NAME" -R "tcp.dstport == $MQTT_LOCAL_PORT || tcp.dstport == $AUTH_CLIENT_PORT" -T fields -e frame.len | wc -l
echo received packet total length
tshark -2 -nr "$FILE_NAME" -R "tcp.dstport == $MQTT_LOCAL_PORT || tcp.dstport == $AUTH_CLIENT_PORT" -T fields -e frame.len | awk '{sum+=$1}END{print sum}'
