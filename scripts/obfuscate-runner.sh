#!/bin/bash

PROGRAM=$1
OUTFILE=$2
LENGTHS=( 1500 3000 4500 6000 7500 9000 )
ALGS=( "SHA256" "ARGON2" ) #"scrypt" )

for alg in "${ALGS[@]}"
do
    for l in "${LENGTHS[@]}"
    do
        echo ${PROGRAM} ${alg} ${l} ${l}
        ${PROGRAM} ${alg} ${l} ${l} >> ${OUTFILE}
    done
done
