#!/bin/bash

FILE_NAME=$1
AUTH_CLIENT_PORT=$2
echo FILE_NAME: "$FILE_NAME", AUTH_CLIENT_PORT: "$AUTH_CLIENT_PORT"
echo sent packet count
tshark -2 -nr "$FILE_NAME" -R "(tcp.dstport >= 21100 && tcp.dstport < 21163) || (tcp.srcport == $AUTH_CLIENT_PORT)" -T fields -e frame.len | wc -l
echo sent packet total length
tshark -2 -nr "$FILE_NAME" -R "(tcp.dstport >= 21100 && tcp.dstport < 21163) || (tcp.srcport == $AUTH_CLIENT_PORT)" -T fields -e frame.len | awk '{sum+=$1}END{print sum}'
echo
echo received packet count
tshark -2 -nr "$FILE_NAME" -R "tcp.srcport >= 21100 && tcp.srcport < 21163 || (tcp.dstport == $AUTH_CLIENT_PORT)" -T fields -e frame.len | wc -l
echo received packet total length
tshark -2 -nr "$FILE_NAME" -R "tcp.srcport >= 21100 && tcp.srcport < 21163 || (tcp.dstport == $AUTH_CLIENT_PORT)" -T fields -e frame.len | awk '{sum+=$1}END{print sum}'
