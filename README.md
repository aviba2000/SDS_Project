# SDS Project
Run the project:
```
sudo systemctl start influxdb
sudo systemctl start telegraf
sudo python3 topology.py
sudo ryu-manager log_packets.py
