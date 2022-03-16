# lab3v1.sh

#!/bin/sh

# Glenn Skawski: Bash file starting OVS, containernet, and POX Controller

# Do sudo -i first

POX_DIR="/home/ubuntu/pox"
cd $POX_DIR

# Use for Lab Assessment Part 3a
#gnome-terminal -- ./pox.py -verbose openflow.of_01 --port=6655 pox.forwarding.l3_learning

# Use for Lab Assessment Part 4
gnome-terminal -- ./pox.py -verbose openflow.of_01 --port=6655 pox.forwarding.l3_learning pox.forwarding.Lab3L3Firewall log.level --DEBUG

export PATH=$PATH:/usr/share/openvswitch/scripts
ovs-ctl start

python3 /home/ubuntu/containernet/cnetlab3v1.py
