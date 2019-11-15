from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.term import makeTerm
from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."
    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        firstHost = self.addHost( 'h1' )
        secondHost = self.addHost( 'h2' )        
        #thirdHost = self.addHost( 'h3' )        
        firstSwitch = self.addSwitch( 's1' )
        secondSwitch = self.addSwitch( 's2' )
        thirdSwitch = self.addSwitch( 's3' )
        fourSwitch = self.addSwitch( 's4' )
                
        # Add links
        self.addLink( firstHost, firstSwitch, port1=1, port2=1 )    #h1-s1
        self.addLink( firstSwitch, thirdSwitch, port1=3, port2=3 )    #s1-s3
        self.addLink( firstSwitch, secondSwitch, port1=2, port2=2 )   #s1-s2                
        self.addLink( secondSwitch, fourSwitch, port1=3, port2=2 )   #s1-s2                
        self.addLink( thirdSwitch, fourSwitch, port1=2, port2=3 )   #s1-s2                
        self.addLink( secondHost, thirdSwitch, port1=1, port2=1 )       #h2-s5
        #self.addLink( thirdHost, secondSwitch )       #h2-s5


topos = { 'mytopo': ( lambda: MyTopo() ) }