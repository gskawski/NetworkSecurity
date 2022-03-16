# Lab3L3Firewall.py

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os
''' New imports here ... '''
import csv
import argparse
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp

log = core.getLogger()
priority = 50000

l2config = "lab3l2firewall.config"
l3config = "lab3l3firewall.config"


class Firewall (EventMixin):

	def __init__ (self,l2config,l3config):
		self.listenTo(core.openflow)
		self.disbaled_MAC_pair = [] # Shore a tuple of MAC pair which will be installed into the flow table of each switch.
		self.fwconfig = list()
		# Glenn Skawski: Table of MAC, IP tuples		
		self.port_table = []

		'''
		Read the CSV file
		'''
		if l2config == "":
			l2config="lab3l2firewall.config"
			
		if l3config == "":
			l3config="lab3l3firewall.config" 
		with open(l2config, 'rb') as rules:
			csvreader = csv.DictReader(rules) # Map into a dictionary
			for line in csvreader:
				# Read MAC address. Convert string to Ethernet address using the EthAddr() function.
                                if line['mac_0'] != 'any':
				    mac_0 = EthAddr(line['mac_0'])
                                else:
                                    mac_0 = None

                                if line['mac_1'] != 'any':
        				mac_1 = EthAddr(line['mac_1'])
                                else:
                                    mac_1 = None
				# Append to the array storing all MAC pair.
				self.disbaled_MAC_pair.append((mac_0,mac_1))

		with open(l3config) as csvfile:
			log.debug("Reading log file 1!")
			self.rules = csv.DictReader(csvfile)
			for row in self.rules:
				log.debug("Saving individual rule parameters in rule dict !")
				s_ip = row['src_ip']
				d_ip = row['dst_ip']
				s_port = row['src_port']
				d_port = row['dst_port']
				print "src_ip, dst_ip, src_port, dst_port", s_ip,d_ip,s_port,d_port

		log.debug("Enabling Firewall Module")

	def replyToARP(self, packet, match, event):
		r = arp()
		r.opcode = arp.REPLY
		r.hwdst = match.dl_src
		r.protosrc = match.nw_dst
		r.protodst = match.nw_src
		r.hwsrc = match.dl_dst
		e = ethernet(type=packet.ARP_TYPE, src = r.hwsrc, dst=r.hwdst)
		e.set_payload(r)
		msg = of.ofp_packet_out()
		msg.data = e.pack()
		msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
		msg.in_port = event.port
		event.connection.send(msg)

	def allowOther(self,event):
		msg = of.ofp_flow_mod()
		match = of.ofp_match()
		action = of.ofp_action_output(port = of.OFPP_NORMAL)
		msg.actions.append(action)
		event.connection.send(msg)

	def installFlow(self, event, offset, srcmac, dstmac, srcip, dstip, sport, dport, nwproto):
		log.debug('install flow reached')
		msg = of.ofp_flow_mod()
		match = of.ofp_match()
		if(srcip != None):
			match.nw_src = IPAddr(srcip)
		if(dstip != None):
			match.nw_dst = IPAddr(dstip)	
		match.nw_proto = int(nwproto)
		match.dl_src = srcmac
		match.dl_dst = dstmac
		match.tp_src = sport
		match.tp_dst = dport
		match.dl_type = pkt.ethernet.IP_TYPE
		msg.match = match
		msg.hard_timeout = 0
		msg.idle_timeout = 0
		msg.priority = priority + offset		
		event.connection.send(msg)

	def replyToIP(self, packet, match, event, fwconfig):
		srcmac = str(match.dl_src)
		dstmac = str(match.dl_src)
		sport = str(match.tp_src)
		dport = str(match.tp_dst)
		nwproto = str(match.nw_proto)

		with open(l3config) as csvfile:
			log.debug("Reading log file 2!")
			self.rules = csv.DictReader(csvfile)
			for row in self.rules:
				log.debug("3!")
				prio = row['priority']
				srcmac = row['src_mac']
				dstmac = row['dst_mac']
				s_ip = row['src_ip']
				d_ip = row['dst_ip']
				s_port = row['src_port']
				d_port = row['dst_port']
				nw_proto = row['nw_proto']
				log.debug("4!")
				log.debug("You are in original code block ...")
				srcmac1 = EthAddr(srcmac) if srcmac != 'any' else None
				dstmac1 = EthAddr(dstmac) if dstmac != 'any' else None
				s_ip1 = s_ip if s_ip != 'any' else None
				d_ip1 = d_ip if d_ip != 'any' else None
				s_port1 = int(s_port) if s_port != 'any' else None
				d_port1 = int(d_port) if d_port != 'any' else None
				prio1 = int(prio) if prio != None else priority
				if nw_proto == "tcp":
					nw_proto1 = pkt.ipv4.TCP_PROTOCOL
				elif nw_proto == "icmp":
					nw_proto1 = pkt.ipv4.ICMP_PROTOCOL
					s_port1 = None
					d_port1 = None
				elif nw_proto == "udp":
					nw_proto1 = pkt.ipv4.UDP_PROTOCOL
				else:
					log.debug("PROTOCOL field is mandatory, Choose between ICMP, TCP, UDP")
				print (prio1,s_ip1, d_ip1, s_port1, d_port1,nw_proto1)
				self.installFlow(event,prio1, srcmac1, dstmac1, s_ip1, d_ip1, s_port1, d_port1, nw_proto1)
		self.allowOther(event)


	def _handle_ConnectionUp (self, event):
		
		log.debug('connectionUp Called')
		
		'''
		Iterate through the disbaled_MAC_pair array, and for each
		pair we install a rule in each OpenFlow switch
		'''
		self.connection = event.connection

		for (source, destination) in self.disbaled_MAC_pair:

			print source,destination
			message = of.ofp_flow_mod() # OpenFlow massage. Instructs a switch to install a flow
			match = of.ofp_match() # Create a match
			match.dl_src = source # Source address

			match.dl_dst = destination # Destination address
			message.priority = 65535 # Set priority (between 0 and 65535)
			message.match = match			
			event.connection.send(message) # Send instruction to the switch

		log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

	def _handle_PacketIn(self, event):
		# Glenn Skawski: Port security code
		log.debug('packetIn Called')

		packet = event.parsed
		match = of.ofp_match.from_packet(packet) # get packet header
		msg = of.ofp_flow_mod() # make rule to allow packet forward
		block = of.ofp_match() # make rule to block packet

		if(match.dl_type == packet.IP_TYPE):

			mac_list = list(filter(lambda mac_IP: mac_IP[0] == match.dl_src, self.port_table)) # temporary list
			if not mac_list: # add mac, ip to port table and reply
				log.debug('if not reached')
				
				self.port_table.append((match.dl_src, match.get_nw_src()[0])) # append new host tuple to port table
				
				for (mac, ip) in self.port_table:
					log.debug('mac is %s - ip is %s', mac, ip)

				# contents of message to switch
				msg.match = match
				msg.command = of.OFPFC_ADD # add forward rule
				msg.buffer_id = event.ofp.buffer_id
				msg.hard_timeout = 60
				msg.idle_timeout = 30
				msg.priority = 50
				msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL)) # normal forwarding
				self.connection.send(msg)
			
			elif(len(mac_list) == 1 and mac_list[0][1] == match.get_nw_src()[0]): # allow normal traffic from MACs with known and matching IP
				log.debug('elif reached')
				
				for (mac, ip) in self.port_table:
					log.debug('mac is %s - ip is %s', mac, ip)
				
				# contents of message to switch
				msg.match = match
				msg.command = of.OFPFC_ADD
				msg.buffer_id = event.ofp.buffer_id
				msg.hard_timeout = 60
				msg.idle_timeout = 30
				msg.priority = 50
				msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
				self.connection.send(msg) #originally event.connection and seems to = self.connection
				
			else: # detect DoS attack and send message to switch to drop future packets
				log.debug('else reached')
				
				block.dl_src = EthAddr(match.dl_src)
				msg.match = block
				msg.command = of.OFPFC_ADD
				msg.hard_timeout = 60
				msg.idle_timeout = 30
				msg.priority = 65535 # priority will be higher than previous rules
				self.connection.send(msg)

		
def launch (l2config="lab3l2firewall.config",l3config="lab3l3firewall.config"):
	'''
	Starting the Firewall module
	'''
	parser = argparse.ArgumentParser()
	parser.add_argument('--l2config', action='store', dest='l2config',
					help='Layer 2 config file', default='lab3l2firewall.config')
	parser.add_argument('--l3config', action='store', dest='l3config',
					help='Layer 3 config file', default='lab3l3firewall.config')
	core.registerNew(Firewall,l2config,l3config)
