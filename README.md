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

### SSH
sudo apt install openssh-server 


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



