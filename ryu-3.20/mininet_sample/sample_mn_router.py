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
    h1 = net.addHost( 'h1', mac='01:00:00:00:01:00', ip='172.16.20.10/24' )
    h2 = net.addHost( 'h2', mac='01:00:00:00:02:00', ip='172.16.10.10/24' )
    h3 = net.addHost( 'h3', mac='01:00:00:00:03:00', ip='192.168.30.10/24' )

    # Create switches
    s1 = net.addSwitch( 's1', listenPort=6634, mac='00:00:00:00:00:01' )
    s2 = net.addSwitch( 's2', listenPort=6634, mac='00:00:00:00:00:02' )
    s3 = net.addSwitch( 's3', listenPort=6634, mac='00:00:00:00:00:03' )

    print "*** Creating links"
    net.addLink(h1, s1 )
    net.addLink(h2, s2 )   
    net.addLink(h3, s3 )   
    net.addLink(s1, s2 )  
    net.addLink(s2, s3 )  

    # Add Controllers
    c0 = net.addController( 'c0', controller=RemoteController, ip=CONTROLLER1_IP, port=6633)

    net.build()

    # Connect each switch to a different controller
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])


    h1.cmd('ip route add default via 172.16.20.1')
    h2.cmd('ip route add default via 172.16.10.1')
    h3.cmd('ip route add default via 192.168.30.1')
    s1.cmdPrint('ovs-vsctl set Bridge s1 protocols=OpenFlow13')
    s1.cmdPrint('ovs-vsctl set Bridge s1 protocols=OpenFlow13')
    s2.cmdPrint('ovs-vsctl set Bridge s2 protocols=OpenFlow13')
    s3.cmdPrint('ovs-vsctl set Bridge s3 protocols=OpenFlow13')

    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNet()

