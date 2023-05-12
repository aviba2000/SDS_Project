# SDS Project

## Requirements

Use ubuntu 20.04!

### Xterm
```
sudo apt install -y xterm
echo “xterm*font: *-fixed-*-*-*-19-*” > .Xresources
xrdb -merge ~/.Xresources
```

### Mininet and Ryu
```
sudo pip3 install ryu mininet
sudo pip3 uninstall eventlet
sudo pip3 install eventlet==0.30.2
```

### Snort
```
sudo apt install snort
sudo ip link add name s1-snort type dummy
sudo ip link set s1-snort up
```

### SSH
```
sudo apt install openssh-server sshpass
```


## How to run
First, set up telegraf and influxdb:

```
docker compose up -d
```

Run the controller and the topology:
```
sudo python3 topology.py
sudo ryu-manager log_packets.py
```

Set up Snort:
```
cp honeypot.rules /etc/snort/rules
```

Modify /etc/snort/snort.conf and add include $RULE_PATH/honeypot.rules.

```
sudo ovs-vsctl add-port s1 s1-snort
```

Run Snort:
```
sudo snort -i s1-snort -A unsock -l /tmp -c /etc/snort/snort.conf
```

Start the worm:
```
h2 ./brute_force_ssh.sh
```

### Show influxdb packets
Access influxdb:

```
docker compose exec influxdb influx
$: influx
```

Then, run the following query:
```
> use RYU
Using database RYU
> select * from unhandled_packets
name: unhandled_packets
time                dst_addr dst_port host         src_addr src_port switch_id
----                -------- -------- ----         -------- -------- ---------
1683824067135514880 10.0.0.1 53598    d3aec3c131ae 10.0.0.2 8080     1
1683824081373686016 10.0.0.2 8080     d3aec3c131ae 10.0.0.1 51102    1
1683824081375801088 10.0.0.1 51102    d3aec3c131ae 10.0.0.2 8080     1
1683824081377064960 10.0.0.1 51102    d3aec3c131ae 10.0.0.2 8080     1
1683824089466955008 10.0.0.1 58978    d3aec3c131ae 10.0.0.2 8080     1
1683824089469122048 10.0.0.1 58978    d3aec3c131ae 10.0.0.2 8080     1
1683824090593255936 10.0.0.1 58982    d3aec3c131ae 10.0.0.2 8080     1
1683824090596761856 10.0.0.1 58982    d3aec3c131ae 10.0.0.2 8080     1
>
```


