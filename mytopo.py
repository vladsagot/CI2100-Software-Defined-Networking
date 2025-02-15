from mininet.topo import Topo


class MyTopo(Topo):

    def build(self):
        # Add hosts and switches
        host1 = self.addHost('h1', ip="10.0.1.100/24", defaultRoute="via 10.0.1.1")
        host2 = self.addHost('h2', ip="10.0.2.100/24", defaultRoute="via 10.0.2.1")
        host3 = self.addHost('h3', ip="10.0.3.100/24", defaultRoute="via 10.0.3.1")
        switch1 = self.addSwitch('s1')

        # Add links
        self.addLink(switch1, host1)
        self.addLink(switch1, host2)
        self.addLink(switch1, host3)


topos = {'mytopo': (lambda: MyTopo())}
