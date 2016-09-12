#!/bin/bash

PROGRAM=$1
URI_FILE=$2
PREFIX_LENGTH=$3

OUTFILE_SHA256=${URI_FILE}_SHA256.out
OUTFILE_Argon2=${URI_FILE}_Argon2.out
touch ${OUTFILE_SHA256}
touch ${OUTFILE_Argon2}

for i in `seq 1 ${PREFIX_LENGTH}`;
do
    echo ${PROGRAM} ${URI_FILE} ${i}
    ${PROGRAM} ${URI_FILE} ${i} 0 >> ${OUTFILE_SHA256}

    # default Argon2 parameters
    ${PROGRAM} ${URI_FILE} ${i} 1 3 12 >> ${OUTFILE_Argon2}
done
