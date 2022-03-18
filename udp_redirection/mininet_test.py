import time

from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.term import makeTerm
from mininet.topo import SingleSwitchTopo


def test():
    topo = SingleSwitchTopo(3)
    net = Mininet(topo=topo, controller=RemoteController, autoSetMacs=True, cleanup=True)
    net.start()

    c0 = net.get('c0')
    s1 = net.get('s1')
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')

    makeTerm(c0, cmd='ryu-manager udp_redirection.py')
    time.sleep(2)
    net.pingAll()

    makeTerm(h1, title='server1', cmd='python3 server1.py')
    makeTerm(h2, title='server2', cmd='python3 server2.py')
    time.sleep(1)

    makeTerm(h3, title='client', cmd='python3 client.py')

    CLI(net)
    net.stopXterms()
    net.stop()


if __name__ == '__main__':
    test()
