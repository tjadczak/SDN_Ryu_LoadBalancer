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
        rightHost = self.addHost( 'h5' )
        SwitchA = self.addSwitch( 's1' )
        SwitchB = self.addSwitch( 's2' )
        SwitchC = self.addSwitch( 's3' )
        SwitchD = self.addSwitch( 's4' )
        SwitchE = self.addSwitch( 's5' )
        
        # Add Links
        self.addLink( leftHost, SwitchA, bw=30 )
        self.addLink( SwitchA, SwitchB, bw=10 )
        self.addLink( SwitchA, SwitchC, bw=10 )
        self.addLink( SwitchA, SwitchD, bw=10 )
        self.addLink( SwitchB, SwitchE, bw=10 )
        self.addLink( SwitchC, SwitchE, bw=10 )
        self.addLink( SwitchD, SwitchE, bw=10 )
        self.addLink( SwitchE, rightHost, bw=30 )
        
topos = { 'mytopo': ( lambda: MyTopo() ) }
