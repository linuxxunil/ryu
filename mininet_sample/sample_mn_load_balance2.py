#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def myNet():
    CONTROLLER1_IP='127.0.0.1'
    
    CONTROLLER2_IP='127.0.0.1'

    net = Mininet( topo=None, build=False)

    # Create server
    sr1 = net.addHost( 'server1', mac='01:00:00:00:01:00', ip='192.168.1.10/24' )
    sr2 = net.addHost( 'server2', mac='01:00:00:00:02:00', ip='192.168.1.11/24' )
    #server3 = net.addHost( 'server3', mac='01:00:00:00:03:00', ip='192.168.1.12/24' )
    
    # Create office
    of1 = net.addHost( 'office1', mac='01:00:00:00:04:00', ip='192.168.0.11/24' )
    of2 = net.addHost( 'office2', mac='01:00:00:00:05:00', ip='192.168.0.12/24' )

    # Create router
    router = net.addSwitch( 's1', listenPort=6634, mac='00:00:00:00:00:01' )
    switch = net.addSwitch( 's2', listenPort=6634, mac='00:00:00:00:00:02' )

    print "*** Creating links"
    net.addLink(sr1, switch )
    net.addLink(sr2, switch )   
    net.addLink(switch, router)   
    net.addLink(of1, router )   
    net.addLink(of2, router )   

    # Add Controllers
    c0 = net.addController( 'c0', controller=RemoteController, ip=CONTROLLER1_IP, port=6633)
    c1 = net.addController( 'c1', controller=RemoteController, ip=CONTROLLER2_IP, port=6634)

    net.build()

    # Connect each switch to a different controller
    switch.start([c0])
    switch.cmdPrint('ovs-vsctl set Bridge s1 protocols=OpenFlow13')
    
    router.start([c1])
    router.cmdPrint('ovs-vsctl set Bridge s1 protocols=OpenFlow13')

    sr1.cmd('route add default gw 192.168.0.1')
    sr2.cmd('route add default gw 192.168.0.1')
    of1.cmd('route add default gw 192.168.1.1')
    of2.cmd('route add default gw 192.168.1.1')


    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNet()

