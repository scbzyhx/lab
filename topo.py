#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel,info
from mininet.node import Controller,RemoteController,Node,OVSController
from mininet.cli import CLI
from mininet.util import quietRun
from mininet.link import TCLink

DPID_BASE = 0
IP_BASE = "192.168.111."
IP_START = 50

def fixNetworkManager( root, intf ):
    """Prevent network-manager from messing with our interface,
    by specifying manual configuration in /etc/network/interfaces
    root: a node in the root namespace (for running commands)
    intf: interface name"""
    cfile = '/etc/network/interfaces'
    line = '\niface %s inet manual\n' % intf
    config = open( cfile ).read()
    if line not in config:
        print '*** Adding', line.strip(), 'to', cfile
        with open( cfile, 'a' ) as f:
            f.write( line )
            # Probably need to restart network-manager to be safe -
            # hopefully this won't disconnect you
            root.cmd( 'service network-manager restart' )

def connectToInternet( network,host ):
    #"Start simple Python web server on hosts"
    info( '*** Starting to connectToInternet\n' )
    #host.cmd( 'cd ./http_%s/; nohup python2.7 ./webserver.py &' % (host.name) )
    root = Node('root',inNamespace = False)
    host = network.get(host)
    #fixNetworkManager(root,'root-eth0')

    #create link
    link = network.addLink(root,host)
    link.intf1.setIP('10.0.0.254',8) #intface on root
    link.intf2.setIP('10.0.0.250',8) #intface on host
    #print '\n\n'
    #print link.intf2
    #print link.intf2.name
    #print '\n\n'
    #network.start()
    info('gateway of mininet ',host.name,'\n')
    startNAT(root,'eth1')
    startNAT(host,link.intf2.name)
    setRoute(host,link.intf2)
    return root

def startNAT(root,inetIntf='eth0',subnet='10.0.0.0/8'):
    "Start NAT betweent victim server and Internet"
    #localIntf = root.defaultIntf()
    #print "local Intf,",root.intfList()
    #print "localIntf,",localIntf
    root.cmd('iptables -F')
    root.cmd('iptables -t nat -F')

    root.cmd('iptables -P INPUT ACCEPT')
    root.cmd('iptables -P OUTPUT ACCEPT')
    root.cmd('iptables -P FORWARD ACCEPT')
    
    #configure NAT

    #root.cmd('iptables -I FORWARD -i', localIntf, '-d', subnet,' -j DROP')
    #root.cmd('iptables -A FORWARD -i', localIntf, '-s', subnet,' -j ACCEPT' )
    #root.cmd('iptables -A FORWARD -i', inetIntf, '-d', subnet, '-j ACCEPT')
    root.cmd('iptables -t nat -A POSTROUTING -o',inetIntf, '-j MASQUERADE')

    root.cmd('sysctl net.ipv4.ip_forward=1')
    root.cmd('sysctl net.ipv4.conf.all.arp_fileter=1')


def stopNAT(root):
    root.cmd('iptables -F')
    root.cmd('iptables -t nat -F')
    root.cmd('sysctl net.ipv4.ip_forward=0')

def setRoute(host,out_intf,subnet='10.0.0.0/8'):
    host.cmd('ip route flush root 0/0')

    host.cmd('route add -net ',IP_BASE+'0/24 ','dev ' ,host.defaultIntf())
    #host.cmd('route add -net ',IP_BASE+'0/24',192.168.0.0/24 dev ' ,host.defaultIntf())
    host.cmd('route add -net',subnet,'dev ',out_intf)#host.defaultIntf())
    host.cmd('route add default gw','10.0.0.254')
    #host.cmd('route add -net 192.168.0.0/24 dev h1-eth1')

    

class MyTopo(Topo):
    "two switch each one"
    def __init__(self,path = None):
        Topo.__init__(self)
        self.my_hosts = {}
        self.my_switches = {}
        self.loadTopoFromFile('config.topo')

    def loadTopoFromFile(self,path):
        with open(path) as filein:
            for line in filein:
                lines = line.strip('\n').split(',')
                if lines[0] == '@':
                    break
                if lines[1] == 'h':
                    self.my_hosts[lines[0]] = self.addHost("h%d" % int(lines[0]))
                elif lines[1] == 's':
                    #print  "%.16d" % (DPID_BASE + int(lines[0]))
                    self.my_switches[lines[0]] = self.addSwitch('s%d' % int(lines[0]),\
                    dpid='%.16d' % (DPID_BASE + int(lines[0])))
            for line in filein:
                print line
                lines = line.strip('\n').split(',')
                if len(lines) < 3:
                    break
                left = None
                right = None
		bw = int(lines[2])
		both_switch = 0
                if lines[0] in self.my_hosts:
                    left = self.my_hosts[lines[0]]
                elif lines[0] in self.my_switches:
                    left = self.my_switches[lines[0]]
		    both_switch += 1

                if lines[1] in self.my_hosts:
                    right = self.my_hosts[lines[1]]
                elif lines[1] in self.my_switches:
                    right = self.my_switches[lines[1]]
		    both_switch += 1
		#if both_switch == 2:
		#    self.addLink(left,right,bw=bw)
		if left != None and right != None:
                    self.addLink(left,right,bw=bw)

def setGateway(host):
    host.cmd('route add default gw',IP_BASE + "%d" % 1)
def setDNS(host):
    host.cmd("echo search nju.edu.cn > /etc/resolv.conf")
    host.cmd("echo nameserver 114.212.11.66 >> /etc/resolv.conf")
    host.cmd("echo nameserver 114.212.11.67 >> /etc/resolv.conf")
def TurnNet():
    info("**start TurnNet\n")
    topoo  = MyTopo()
    info("** creating network\n")
    net = Mininet(topo = topoo, controller = lambda name : RemoteController(name,ip = '114.212.85.130'),link = TCLink)
    for h in topoo.my_hosts.keys():
        host = net.get('h'+h)
        host.setIP(IP_BASE + "%d" %(IP_START+int(h)),24)
        if host.name == 'h1':
            host.setIP(IP_BASE + "%d" % 1, 24)
        else:
            setDNS(host)
            host.setIP(IP_BASE + "%d" %(IP_START+int(h)),24)
            setGateway(host)

    root = connectToInternet(net,'h1')
    net.start()
    CLI(net)
    root.terminate()
    net.stop()
    #net.stop()

if __name__=="__main__":
    setLogLevel("info")
    TurnNet()
    
