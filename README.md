# SDS Project

## Requirements

Use ubuntu 20.04!

First, clone the repo and init submodules:

```bash
git clone https://github.com/aviba2000/SDS_Project.git
git submodule update --init --recursive
```

Execute the setup script:
```bash
sudo setup.sh
```

## Set up
Set up Snort:

```
cp honeypot.rules /etc/snort/rules
```

Modify /etc/snort/snort.conf and add include $RULE_PATH/honeypot.rules.

## How to run
Running:

```
docker compose up -d
```

This will start the following containers:
- **influxdb**: 127.0.0.1:8086
- **telegraf**: 127.0.0.1:8094

Start ryu-manager with flow manager visor:
```
sudo ryu-manager --observe-links flowmanager/flowmanager.py log_packets.py
```

This will start:
- **ryu manager**: 127.0.0.1:6653
- **flow manager visor**: http://localhost:8080/home/index.html


Set up topology:
```
sudo python3 topology.py
```

Add snort:
```
sudo ovs-vsctl add-port s1 s1-snort
```

Run Snort:
```
sudo snort -i s1-snort -A unsock -l /tmp -c /etc/snort/snort.conf
```

Start the worm:
```
mininet> h2 ./brute_force_ssh.sh 2
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

### Reattach a host that has been removed from the network
The idea consists of reattaching the port of the switch.
```
sudo ovs-vsctl add-port s1 s1-eth3
```
