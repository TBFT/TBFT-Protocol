#!/bin/bash

COUNTER=0
while [ $COUNTER -lt 16 ]
do
    bin/peer --id=$COUNTER request > log/$COUNTER.txt &
    let COUNTER+=1
done
