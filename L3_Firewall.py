from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr,dpid_to_str
from pox.lib.addresses import EthAddr, IPAddr
import pox.lib.packet as pkt
from pox.lib.util import str_to_bool
from collections import namedtuple
import os
import csv
import time

log = core.getLogger()
policyFile = "/home/mininet/pox/pox/misc/firewallpolicies_ver5.csv"

class Firewall(object):

    def __init__ (self,connection,transparent):
	self.connection = connection
	self.transparent = transparent
	connection.addListeners(self)
        log.info("Enabling Firewall Module")
        # Our firewall table
        self.firewall = {}
	self.macToPort = {}
	self.policies()

    def sendRule (self, src, dst, duration = 0):
        """
        Drops this packet and optionally installs a flow to continue
        dropping similar ones for a while
        """
        if not isinstance(duration, tuple):
            duration = (duration,duration)

        msg = of.ofp_flow_mod()
	msg.match.dl_type = 0x800
	#msg.match.nw_proto = pkt.ipv4.ICMP_PROTOCOL
        msg.match.nw_src = IPAddr(src)
        msg.match.nw_dst = IPAddr(dst)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.priority = 65535
        self.connection.send(msg)

	msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x806
        #msg.match.nw_proto = pkt.ipv4.ICMP_PROTOCOL
        msg.match.nw_src = IPAddr(src)
        msg.match.nw_dst = IPAddr(dst)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.priority = 65535
        self.connection.send(msg)

    # function that allows adding firewall rules into the firewall table
    def AddRule (self, src=0, dst=0, value=True):
        if (src, dst) in self.firewall:
            log.info("Rule already present drop: src %s - dst %s", src, dst)
        else:
            log.info("Adding firewall rule drop: src %s - dst %s", src, dst)
            self.firewall[(src, dst)]=value
	    print "Adding:",self.firewall
            self.sendRule(src, dst, 10000)

    # function that allows deleting firewall rules from the firewall table
    def DeleteRule (self, src=0, dst=0):
        try:
            del self.firewall[(src, dst)]
            sendRule(src, dst, 0)
            log.info("Deleting firewall rule drop: src %s - dst %s", src, dst)
        except KeyError:
            log.error("Cannot find in rule drop src %s - dst %s", src, dst)

    def policies(self):
        ''' Add your logic here ... '''
        ifile  = open(policyFile, "rb")
        reader = csv.reader(ifile)
        rownum = 0
        for row in reader:
            # Save header row.
            if rownum == 0:
                header = row
            else:
                colnum = 0
                for col in row:
                    #print '%-8s: %s' % (header[colnum], col)
                    colnum += 1
		#print "Row[0]: ", row[0], type(int(row[0]))
		#print "event.dpid: ",event.dpid, type(event.dpid)
		if int(row[0]) == self.connection.dpid:
			if str(row[3]).lower() == 'drop':
                		self.AddRule(IPAddr(row[1]), IPAddr(row[2]))

            rownum += 1
        ifile.close()

        log.info("Firewall rules installed on %s", dpidToStr(self.connection.dpid))

    def _handle_PacketIn (self, event):
    
    	packet = event.parsed
	ipp = packet.find('ipv4')

    	def flood(message = None):
      		msg = of.ofp_packet_out()

        	if message is not None: 
			log.debug(message)
        
        	msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        	#log.info("Holding down flood for %s", dpid_to_str(event.dpid))
      		msg.data = event.ofp
      		msg.in_port = event.port
      		self.connection.send(msg)

   	def drop (duration = None):
      		if duration is not None:
        		if not isinstance(duration, tuple):
          			duration = (duration,duration)
        		msg = of.ofp_flow_mod()
        		msg.match = of.ofp_match.from_packet(packet)
        		msg.idle_timeout = duration[0]
			msg.hard_timeout = duration[1]
        		msg.buffer_id = event.ofp.buffer_id
        		self.connection.send(msg)
      		elif event.ofp.buffer_id is not None:
        		msg = of.ofp_packet_out()
        		msg.buffer_id = event.ofp.buffer_id
       		 	msg.in_port = event.port
        		self.connection.send(msg)


   	

	#DPID of the switch connection
    	dpid_switch = event.connection.dpid

    	self.macToPort[packet.src] = event.port # 1

	if ipp:
		print "Checking:", ipp.srcip,ipp.dstip
		if (ipp.srcip,ipp.dstip) in self.firewall:
			drop()
			return


   	if not self.transparent: # 2
      		if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
        		drop() # 2a
        		return

    	if packet.dst.is_multicast:
      		flood() # 3a
    	else:
     	 	if packet.dst not in self.macToPort.keys(): # 4
        		flood("Port for %s unknown -- flooding" % (packet.dst,)) # 4a
      		else:
        		port = self.macToPort[packet.dst]
        		if port == event.port: # 5
          		# 5a
          			log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
              				% (packet.src, packet.dst, dpid_to_str(event.dpid), port))
          			drop(10)
          			return

			log.debug("installing flow for %s.%i -> %s.%i" %
                  		(packet.src, event.port, packet.dst, port))
        		msg = of.ofp_flow_mod()
       		 	msg.match = of.ofp_match.from_packet(packet, event.port)
       			msg.priority = 30
        		msg.actions.append(of.ofp_action_output(port = port))
        		msg.data = event.ofp # 6a
        		self.connection.send(msg)


       
class startup(object):
	def __init__(self,transparent):
		core.openflow.addListeners(self)
		self.transparent = transparent

	def _handle_ConnectionUp(self,event):
		Firewall(event.connection,self.transparent)


def launch (transparent=False):
    '''
    Starting the Firewall module
    '''
    core.registerNew(startup,str_to_bool(transparent))

