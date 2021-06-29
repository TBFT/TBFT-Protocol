#!/bin/bash

COUNTER=0
while [ $COUNTER -lt 3 ]
do
    bin/peer run $COUNTER > replica/$COUNTER.txt 2>replica/log$COUNTER.txt  &
    let COUNTER+=1
done
