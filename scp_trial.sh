#!/bin/bash

RUN_COUNT="5"
TIMEFORMAT="%3R"
CIPHERS=(
    "3des-cbc"
    "aes128-cbc"
    "aes192-cbc"
    "aes256-cbc"
    "aes128-ctr"
    "aes192-ctr"
    "aes256-ctr"
    "arcfour"
    "arcfour128"
    "arcfour256"
    "blowfish-cbc"
    "cast128-cbc")

if [ -z "$2" ]; then
    echo usage: $0 \<user\> \<host\>
    exit 1
fi

SCP_USER=$1
SCP_HOST=$2

# Dry run to establish connection to host
/usr/bin/scp -q plain.bin ${SCP_USER}@${SCP_HOST}:/dev/null

for cipher in ${CIPHERS[@]}; do
    echo ${cipher}
    count=${RUN_COUNT}
    while [ ${count} -gt 0 ]; do
        # Write to /dev/null to avoid delays from remote filesystem
        time /usr/bin/scp -q -c ${cipher} plain.bin ${SCP_USER}@${SCP_HOST}:/dev/null
        count=$[$count - 1]
    done
done

exit 0
