#!/bin/bash

allPorts=("s1-eth1" "s1-eth2" "s1-eth3" "s2-eth1" "s2-eth2" "s2-eth3" "s2-eth4" "s3-eth1" "s3-eth2" "s3-eth3")
for port in "${allPorts[@]}"
do
  switch=$(echo "$port" | cut -d '-' -f 1)
  ovs-vsctl add-port "$switch" "$port" 2> /dev/null
done
