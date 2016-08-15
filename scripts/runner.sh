#!/bin/bash

PROGRAM=$1
URI_FILE=$2
PREFIX_LENGTH=$3

OUTFILE=${URI_FILE}.out
touch ${OUTFILE}

for i in `seq 1 ${PREFIX_LENGTH}`;
do
    echo ${PROGRAM} ${URI_FILE} ${i}
    ${PROGRAM} ${URI_FILE} ${i} >> ${OUTFILE}
done
