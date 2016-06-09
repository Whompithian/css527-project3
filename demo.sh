#! /bin/bash

PROMPT="\e[0;32m${USER}@${HOSTNAME}:\e[01;34m~$ \e[0m"

if [ -z "$2" ]; then
    echo -e "${PROMPT}sudo apt-get install python-crypto python-gnupg python-pip"
    sudo apt-get install python-crypto python-gnupg python-pip
    echo -e "${PROMPT}sudo pip install cryptography"
    sudo pip install cryptography
    echo ""
    echo "Need to specify target for scp."
    echo "Run again as: $0 \<user\> \<host\>"
    exit 1
fi

SCP_USER=$1
SCP_HOST=$2

echo -e "${PROMPT}./algo.py"
./algo.py
echo -e "${PROMPT}./scp_trial.sh ${SCP_USER} ${SCP_HOST}"
./scp_trial.sh ${SCP_USER} ${SCP_HOST}

exit 0
