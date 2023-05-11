from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController

net = Mininet(topo = None, controller=RemoteController)

s1 = net.addSwitch('s1', protocols="OpenFlow13")
s2 = net.addSwitch('s2', protocols="OpenFlow13")
s3 = net.addSwitch('s3', protocols="OpenFlow13")
h1 = net.addHost('h1', ip = '10.0.0.1')
h2 = net.addHost('h2', ip = '10.0.0.2')
h3 = net.addHost('h3', ip = '10.0.0.3')
h4 = net.addHost('h4', ip = '10.0.0.4')
h5 = net.addHost('h5', ip = '10.0.0.5')
h6 = net.addHost('h6', ip = '10.0.0.6')

c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

# Add (bidirectional) links for hosts
net.addLink(h1, s1)
net.addLink(h2, s1)
net.addLink(h3, s2)
net.addLink(h4, s2)
net.addLink(h5, s3)
net.addLink(h6, s3)

# Add (bidirectional) links for switches
net.addLink(s1, s2)
net.addLink(s2, s3)
# net.addLink(s3, s1) # NO LOOPS! or it breaks...

for h in net.hosts:
	h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")

# We start ssh server in h1, you need OpenSSH-server installed in your machine
for h in net.hosts:
	h.cmd('[ ! -d "/run/sshd" ] && mkdir /run/sshd && chmod 0755 /run/sshd')
	h.cmd("/usr/sbin/sshd -D &")


net.start()
CLI(net)
net.stop()
'''
h1.cmd('[ ! -d "/run/sshd" ] && mkdir /run/sshd && chmod 0755 /run/sshd')
h1.cmd('useradd h1 -p h1')
h1.cmd('su h1')
# h1.cmd("/usr/sbin/sshd -D &")
h1.cmd("sudo /usr/sbin/sshd -D")



[ ! -d "/run/sshd" ] && mkdir /run/sshd && chmod 0755 /run/sshd

/usr/sbin/sshd -D &
mkdir /run/sshd && chmod 0755 /run/sshd
h2 ssh albert@10.0.0.1


'''
