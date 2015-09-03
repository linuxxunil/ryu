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
    #h1 = net.addHost( 'h1', mac='01:00:00:00:01:00', ip='192.168.0.1/24' )
    #h2 = net.addHost( 'h2', mac='01:00:00:00:02:00', ip='192.168.0.2/24' )

    # Create switches
    s1 = net.addSwitch( 's1', listenPort=6634, mac='00:00:00:00:00:01' )
    s2 = net.addSwitch( 's2', listenPort=6634, mac='00:00:00:00:00:02' )
    s3 = net.addSwitch( 's3', listenPort=6635, mac='00:00:00:00:00:03' )
    s4 = net.addSwitch( 's4', listenPort=6635, mac='00:00:00:00:00:04' )
    s5 = net.addSwitch( 's5', listenPort=6635, mac='00:00:00:00:00:05' )

    print "*** Creating links"  
    net.addLink(s1, s2 )  
    net.addLink(s2, s3 )  
    net.addLink(s1, s4 )  
    net.addLink(node1=s1, port1=3, node2=s1, port2=4)
    net.addLink(s1, s5) #for echo server
    
    # Add Controllers
    c0 = net.addController( 'c0', controller=RemoteController, ip=CONTROLLER1_IP, port=6633)

    c1 = net.addController( 'c1', controller=RemoteController, ip=CONTROLLER2_IP, port=6644)


    net.build()

    # Connect each switch to a different controller
    s1.start([c0])
    s2.start([c1])
    s3.start([c1])
    s4.start([c0])
    s5.start([c0])

    s1.cmd('ovs-vsctl show')
    
    s5.cmdPrint('curl -X DELETE http://ubuntu:8080/stats/flowentry/clear/0000000000000005')
    s5.cmdPrint('curl -X POST -d \'{"dpid":"0000000000000005","priority": 65535, "match": {"in_port":1}, "cookie":0, "actions":[{"type":"OUTPUT","port":"4294967288"}]}\' http://ubuntu:8080/stats/flowentry/add')
    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNet()

