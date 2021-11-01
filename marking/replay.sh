#!/bin/bash

PUT=$1
FOLDER=$2

for f in $(echo $FOLDER/id*)
do
  aflnet-replay $f FOTBOT 8888 > /dev/null 2>&1 & $PUT 127.0.0.1 8888
done
