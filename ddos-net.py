#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Node
from mininet.node import RemoteController
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf, OVSLink
from mininet.cli import CLI
from mininet.node import OVSKernelSwitch, UserSwitch


class LinuxRouter(Node):

    def config(self, **params):

        super(LinuxRouter, self).config(**params)

        self.cmd('sysctl net.ipv4.ip_forward=1')


    def terminate(self):

        self.cmd('sysctl net.ipv4.ip_forward=0')

        super(LinuxRouter, self).terminate()



def create_net():

    net = Mininet( topo=None,
                   build=False,
                   link=OVSLink,
                   ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip='172.18.0.1',
                      protocol='tcp',
                      port=6653)
    
    s5 = net.addSwitch('s5', cls=OVSKernelSwitch, protocols=["OpenFlow13"])
    s6 = net.addSwitch('s6', cls=OVSKernelSwitch, protocols=["OpenFlow13"])
    s7 = net.addSwitch('s7', cls=OVSKernelSwitch, protocols=["OpenFlow13"])
    s8 = net.addSwitch('s8', cls=OVSKernelSwitch, protocols=["OpenFlow13"])

    # Add 4 routers in four different subnets
    r1 = net.addHost('r1', cls=LinuxRouter, ip='10.0.0.1/24')
    r2 = net.addHost('r2', cls=LinuxRouter, ip='10.1.0.1/24')
    r3 = net.addHost('r3', cls=LinuxRouter, ip='10.2.0.1/24')
    r4 = net.addHost('r4', cls=LinuxRouter, ip='10.3.0.1/24')

    # Add host-switch links in the same subnet

    net.addLink(s5,
                r1,
                intfName2='r1-eth1',
                params2={'ip': '10.0.0.1/24'})


    net.addLink(s6,
                r2,
                intfName2='r2-eth1',
                params2={'ip': '10.1.0.1/24'})


    net.addLink(s7,
                r3,
                intfName2='r3-eth1',
                params2={'ip': '10.2.0.1/24'})


    net.addLink(s8,
                r4,
                intfName2='r4-eth1',
                params2={'ip': '10.3.0.1/24'})


    # Add router-router links in new subnets for the router-router connections

    net.addLink(r1,
                r2,
                intfName1='r1-eth2',
                intfName2='r2-eth2',
                params1={'ip': '10.100.0.1/24'},
                params2={'ip': '10.100.0.2/24'})


    net.addLink(r1,
                r3,
                intfName1='r1-eth3',
                intfName2='r3-eth2',
                params1={'ip': '10.101.0.1/24'},
                params2={'ip': '10.101.0.2/24'})


    net.addLink(r3,
                r4,
                intfName1='r3-eth3',
                intfName2='r4-eth2',
                params1={'ip': '10.102.0.1/24'},
                params2={'ip': '10.102.0.2/24'})


    net.addLink(r2,
                r4,
                intfName1='r2-eth3',
                intfName2='r4-eth3',
                params1={'ip': '10.103.0.1/24'},
                params2={'ip': '10.103.0.2/24'})


    # Adding hosts specifying the default route
    h1 = net.addHost(name='h1',
                    ip='10.0.0.9/24',
                    defaultRoute='via 10.0.0.1')
    h2 = net.addHost(name='h2',
                    ip='10.0.0.10/24',
                    defaultRoute='via 10.0.0.1')
    h3 = net.addHost(name='h3',
                    ip='10.1.0.9/24',
                    defaultRoute='via 10.1.0.1')
    h4 = net.addHost(name='h4',
                    ip='10.1.0.10/24',
                    defaultRoute='via 10.1.0.1')
    h5= net.addHost(name='h5',
                    ip='10.2.0.9/24',
                    defaultRoute='via 10.2.0.1')
    h6 = net.addHost(name='h6',
                    ip='10.2.0.10/24',
                    defaultRoute='via 10.2.0.1')

    h7 = net.addHost(name='h7',
                    ip='10.3.0.9/24',
                    defaultRoute='via 10.3.0.1')
    h8 = net.addHost(name='h8',
                    ip='10.3.0.10/24',
                    defaultRoute='via 10.3.0.1')


    # Add host-switch links

    net.addLink(h1, s5)
    net.addLink(h2, s5)
    net.addLink(h3, s6)
    net.addLink(h4, s6)
    net.addLink(h5, s7)
    net.addLink(h6, s7)
    net.addLink(h7, s8)
    net.addLink(h8, s8)

    # Add routing for reaching networks that aren't directly connected

    info(net['r1'].cmd("ip route add 10.1.0.0/24 via 10.100.0.2 dev r1-eth2"))
    info(net['r1'].cmd("ip route add 10.2.0.0/24 via 10.101.0.2 dev r1-eth3"))
    info(net['r1'].cmd("ip route add 10.3.0.0/24 via 10.101.0.2 dev r1-eth3"))
    info(net['r1'].cmd("ip route add 10.3.0.0/24 via 10.100.0.2 dev r1-eth2"))


    info(net['r2'].cmd("ip route add 10.0.0.0/24 via 10.100.0.1 dev r2-eth2"))
    info(net['r2'].cmd("ip route add 10.3.0.0/24 via 10.103.0.2 dev r2-eth3"))
    info(net['r2'].cmd("ip route add 10.2.0.0/24 via 10.103.0.2 dev r2-eth3"))
    info(net['r2'].cmd("ip route add 10.2.0.0/24 via 10.100.0.1 dev r2-eth2"))


    info(net['r3'].cmd("ip route add 10.0.0.0/24 via 10.101.0.1 dev r3-eth2"))
    info(net['r3'].cmd("ip route add 10.3.0.0/24 via 10.102.0.2 dev r3-eth3"))
    info(net['r3'].cmd("ip route add 10.1.0.0/24 via 10.102.0.2 dev r3-eth3"))
    info(net['r3'].cmd("ip route add 10.1.0.0/24 via 10.101.0.1 dev r3-eth2"))


    info(net['r4'].cmd("ip route add 10.1.0.0/24 via 10.103.0.1 dev r4-eth3"))
    info(net['r4'].cmd("ip route add 10.2.0.0/24 via 10.102.0.1 dev r4-eth2"))
    info(net['r4'].cmd("ip route add 10.0.0.0/24 via 10.102.0.1 dev r4-eth2"))
    info(net['r4'].cmd("ip route add 10.0.0.0/24 via 10.103.0.1 dev r4-eth3"))

    info(net['r2'].cmd("ip route add 10.101.0.0/24 via 10.100.0.1 dev r2-eth2"))
    info(net['r2'].cmd("ip route add 10.102.0.0/24 via 10.103.0.2 dev r2-eth3"))
    info(net['r4'].cmd("ip route add 10.101.0.0/24 via 10.102.0.1 dev r4-eth2"))
    info(net['r4'].cmd("ip route add 10.100.0.0/24 via 10.103.0.1 dev r4-eth3"))


    net.start()
    CLI(net)
    net.stop()



if __name__ == '__main__':

    setLogLevel('info')
    create_net()