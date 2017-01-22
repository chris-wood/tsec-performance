#!/bin/bash

PROGRAM=$1
OUTFILE=$2
LENGTHS=( 1500 3000 4500 6000 7500 9000 )
ALGS=( "SHA256 0 0" "ARGON2 4 33554432" "ARGON2 4 2097152" "ARGON2 4 134217728")

for alg in "${ALGS[@]}"
do
    for l in "${LENGTHS[@]}"
    do
        echo ${PROGRAM} ${l} ${l} ${alg}
        ${PROGRAM} ${l} ${l} ${alg} >> ${OUTFILE}
    done
done
