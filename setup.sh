#!/bin/bash

# Check if Docker is installed
if ! command -v docker &> /dev/null
then
    # If not install Docker
    echo "Docker is not installed. Installing now..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
    echo "Docker has been installed successfully!"
else
    # Docker is already installed
    echo "Docker is already installed."
fi

# Install Xterm
sudo apt install -y xterm
echo “xterm*font: *-fixed-*-*-*-19-*” > .Xresources
xrdb -merge ~/.Xresources

# Install Mininet and Ryu
sudo pip3 install ryu mininet
sudo pip3 uninstall eventlet
sudo pip3 install eventlet==0.30.2

# Install Snort
sudo apt install snort
sudo ip link add name s1-snort type dummy
sudo ip link set s1-snort up

# Install SSH
sudo apt install openssh-server sshpass