"""
Custom topology example
Two directly connected switches plus a host for each switch:
    host ---switch ---switch ---host
Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
class MyTopo( Topo ):
    def __init__( self ):
        # Initialize topology
        Topo.__init__( self )
        
        # Add hosts and switches
        leftHost = self.addHost( 'h1' )
        rightHost = self.addHost( 'h3' )
        SwitchA = self.addSwitch( 's1' )
        SwitchB = self.addSwitch( 's21' )
        SwitchC = self.addSwitch( 's22' )
        SwitchD = self.addSwitch( 's23' )
        SwitchE = self.addSwitch( 's3' )
        
        # Add links
        self.addLink( leftHost, SwitchA )
        self.addLink( SwitchA, SwitchB )
        self.addLink( SwitchA, SwitchC )
        self.addLink( SwitchA, SwitchD )
        self.addLink( SwitchB, SwitchE )
        self.addLink( SwitchC, SwitchE )
        self.addLink( SwitchD, SwitchE )
        self.addLink( SwitchE, rightHost )
        
topos = { 'mytopo': ( lambda: MyTopo() ) }
