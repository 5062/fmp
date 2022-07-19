from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController, Controller, OVSSwitch
from mininet.term import makeTerm


class OptionalRemoteController(RemoteController):
    def __init__(self, name, ip, port=None, **kwargs):
        Controller.__init__(self, name, ip=ip, port=port, **kwargs)

    def checkListening(self):
        """Ignore controller not accessible warning"""
        pass

    def stop(self):
        super(Controller, self).stop(deleteIntfs=True)


def create_network():
    """
    Ryu and Snort on the same machine
    Ryu receives Snort alert packet via Unix Domain Socket

    +-----------------------------------+
    |              unixsock             |
    |    Ryu  <---------------- Snort   |
    |                 c0                |
    +--c0-eth0-----------------c0-eth1--+
      10.0.1.1                    |
          |                       |
          |                       |
      10.0.0.10                   |
    +--s1-eth4-----------------s1-eth5--+
    |                 s1                |
    |                                   |
    +--s1-eth1-----s1-eth2-----s1-eth3--+
          |           |           |
          |           |           |
       h1-eth0     h2-eth0     h3-eth0
      10.0.0.1    10.0.0.2    10.0.0.3
      +------+    +------+    +------+
      |  h1  |    |  h2  |    |  h3  |
      +------+    +------+    +------+
    """

    net = Mininet(controller=None, build=False, cleanup=True)

    net.addController('c0', OptionalRemoteController, ip='10.0.1.1', port=6653)

    s1 = net.addSwitch('s1', cls=OVSSwitch, failmode='standalone')

    h1 = net.addHost('h1')
    h2 = net.addHost('h2')
    h3 = net.addHost('h3')
    c0 = net.addHost('c0')

    link_h1s1 = net.addLink(h1, s1, intfName1='h1-eth0', intfName2='s1-eth1')
    link_h2s1 = net.addLink(h2, s1, intfName1='h2-eth0', intfName2='s1-eth2')
    link_h3s1 = net.addLink(h3, s1, intfName1='h3-eth0', intfName2='s1-eth3')

    link_c0p0s1 = net.addLink(c0, s1, intfName1='c0-eth0', intfName2='s1-eth4')  # ryu-s1
    link_c0p1s1 = net.addLink(c0, s1, intfName1='c0-eth1', intfName2='s1-eth5')  # snort-s1

    net.build()

    link_h1s1.intf1.config(mac='00:00:00:00:00:01', ip='10.0.0.1/24')
    link_h2s1.intf1.config(mac='00:00:00:00:00:02', ip='10.0.0.2/24')
    link_h3s1.intf1.config(mac='00:00:00:00:00:03', ip='10.0.0.3/24')

    link_c0p0s1.intf1.config(mac='00:00:00:00:00:04', ip='10.0.1.1/24')
    link_c0p0s1.intf2.config(ip='10.0.0.10/24')

    c0.cmd('ip route add 10.0.0.10/32 via 10.0.1.1 dev c0-eth0')
    s1.cmd('ip route add 10.0.1.1/32 via 10.0.0.10 dev s1-eth4')

    c0.cmd('ifconfig c0-eth1 promisc')

    return net


if __name__ == '__main__':
    net = create_network()
    net.start()

    c0 = net.get('c0')
    s1 = net.get('s1')
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')

    makeTerm(c0)
    makeTerm(s1)
    makeTerm(h1)
    makeTerm(h2)
    makeTerm(h3)

    CLI(net)
    net.stopXterms()
    net.stop()
