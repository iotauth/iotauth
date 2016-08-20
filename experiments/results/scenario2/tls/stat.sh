#!/bin/bash

FILE_NAME=$1
echo FILE_NAME: "$FILE_NAME"
echo sent packet count
tshark -2 -nr "$FILE_NAME" -R "tcp.srcport == 21100" -T fields -e frame.len | wc -l
echo sent packet total length
tshark -2 -nr "$FILE_NAME" -R "tcp.srcport == 21100" -T fields -e frame.len | awk '{sum+=$1}END{print sum}'
echo
echo received packet count
tshark -2 -nr "$FILE_NAME" -R "tcp.dstport == 21100" -T fields -e frame.len | wc -l
echo received packet total length
tshark -2 -nr "$FILE_NAME" -R "tcp.dstport == 21100" -T fields -e frame.len | awk '{sum+=$1}END{print sum}'
