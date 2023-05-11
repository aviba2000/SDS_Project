# SDS Project
Run the topology:
```
sudo python3 topology.py
sudo ryu-manager --verbose ryu/simple_switch_rest_13.py
```
Start InfluxDB:
```
sudo systemctl start influxdb
```
Start telegraf:
```
sudo systemctl start telegraf
```
Start Ryu controller:
```
ryu-manager log_packets.py
```
