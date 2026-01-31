#!/bin/bash
PID=`ps -ef | grep ruc_ | grep -v grep | awk '{print $2}'`
for item in $PID
do
    kill $item
done