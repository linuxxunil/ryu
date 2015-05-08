#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def myNet():
    #OpenDayLight controller
    CONTROLLER1_IP='127.0.0.1'

    #Floodlight controller
    CONTROLLER2_IP='127.0.0.1'

    net = Mininet( topo=None, build=False)

    # Create nodes
    h1 = net.addHost( 'h1', mac='01:00:00:00:01:00', ip='192.168.1.10/24' )
    h2 = net.addHost( 'h2', mac='01:00:00:00:02:00', ip='192.168.1.11/24' )

    # Create switches
    s1 = net.addSwitch( 's1', listenPort=6634, mac='00:00:00:00:00:01' )

    print "*** Creating links"
    net.addLink(h1, s1, )
    net.addLink(h2, s1, )   

    # Add Controllers
    c0 = net.addController( 'c0', controller=RemoteController, ip=CONTROLLER1_IP, port=6633)

    net.build()

    # Connect each switch to a different controller
    s1.start([c0])

    #h1.cmd('ip route add default via 172.16.20.1')
    #h2.cmd('ip route add default via 172.16.10.1')
    s1.cmdPrint('ovs-vsctl set Bridge s1 protocols=OpenFlow13')

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNet()

