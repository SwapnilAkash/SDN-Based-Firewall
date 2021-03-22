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
policyFile = "/home/mininet/pox/pox/misc/firewallpolicies_ver6.csv"

class Firewall(object):

    def __init__ (self,connection,transparent):
	self.connection = connection
	self.transparent = transparent
	connection.addListeners(self)
        log.info("Enabling Firewall Module")
        # Our firewall table
        self.firewall = {}
	self.macToPort = {}
	self.forward_priority = []
	self.priority = 65535
	self.priority_index = 0
	self.forward_tcp_src = 0
	self.forward_tcp_dst = 0
	self.policies()

    def sendRule (self, src, dst, src_port, dst_port, priority, duration = 0):
        
        if not isinstance(duration, tuple):
            duration = (duration,duration)

        msg = of.ofp_flow_mod()
	msg.match.dl_type = 0x800
	#msg.match.nw_proto = pkt.ipv4.ICMP_PROTOCOL
        msg.match.nw_src = IPAddr(src)
        msg.match.nw_dst = IPAddr(dst)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
	if isinstance(src_port, int):
		msg.match.nw_proto = 6
		msg.match.tp_src = src_port
	
	if isinstance(dst_port, int):
		msg.match.nw_proto = 6
                msg.match.tp_dst = dst_port

        msg.priority = priority
        self.connection.send(msg)
	'''
	msg = of.ofp_flow_mod()
        msg.match.dl_type = 0x806
        #msg.match.nw_proto = pkt.ipv4.ICMP_PROTOCOL
        msg.match.nw_src = IPAddr(src)
        msg.match.nw_dst = IPAddr(dst)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.priority = 65535
        self.connection.send(msg)
	'''
    # function that allows adding firewall rules into the firewall table
    def AddRule (self, src=0, dst=0, src_port=0, dst_port=0, priority=0, value=True):
        if (src, dst, src_port, dst_port) in self.firewall:
            log.info("Rule already present drop: src %s - dst %s : %s - %s", src, dst, src_port, dst_port)
        else:
            log.info("Adding firewall rule drop: src %s - dst %s : %s - %s", src, dst, src_port, dst_port)
            self.firewall[(src, dst, src_port, dst_port)] = value
	    print "Adding:",self.firewall
            self.sendRule(src, dst, src_port, dst_port, priority, 10000)

    # function that allows deleting firewall rules from the firewall table
    def DeleteRule (self, src, dst, src_port, dst_port):
        try:
            del self.firewall[(src, dst, src_port, dst_port)]
            sendRule(src, dst, src_port, dst_port, 0)
            log.info("Deleting firewall rule drop: src %s - dst %s : %s", src, dst, src_port, dst_port)
        except KeyError:
            log.error("Cannot find in rule drop src %s - dst %s : %s", src, dst, src_port, dst_port)

    
    def policies(self):
        ifile  = open(policyFile, "rb")
        reader = csv.reader(ifile)
        rownum = 0
	flag = 0
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
			flag = flag + 1
			self.priority = self.priority if flag == 1 else self.priority - 1
			if str(row[5]).lower() == 'forward':
				self.forward_priority.append(self.priority)
				self.forward_tcp_src = '*' if row[3] == '*' else int(row[3])
                                self.forward_tcp_dst = '*' if row[4] == '*' else int(row[4])


			elif str(row[5]).lower() == 'drop':
				#self.priority = self.priority if flag == 1 else priority - 1
				tcp_src = '*' if row[3] == '*' else int(row[3])
				tcp_dst = '*' if row[4] == '*' else int(row[4])
				self.AddRule(IPAddr(row[1]), IPAddr(row[2]), tcp_src, tcp_dst, self.priority)

            rownum = rownum + 1
        ifile.close()

        log.info("Firewall rules installed on %s", dpidToStr(self.connection.dpid))


    def _handle_PacketIn (self, event):
    
    	packet = event.parsed
	ipp = packet.find('ipv4')
	tcpp = packet.find('tcp')

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
		if tcpp:
			print "Checking:{} -> {} : {} - {}".format(ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport)
			if (ipp.srcip,ipp.dstip,tcpp.srcport,tcpp.dstport) in self.firewall:
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
			if ipp:
				if not self.forward_priority and self.priority_index < len(self.forward_priority):
					msg.priority = self.forward_priority[self.priority_index]
					self.priority_index = self.priority_index + 1
				else:
					msg.priority = 30
			else:
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

