#!/usr/bin/python
# -*- coding: utf-8 -*-
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ipv4, tcp, udp, ethernet
from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ether_types
from ryu.lib import snortlib

import socket
import datetime

# Telegraph server
UDP_IP = "127.0.0.1"
UDP_PORT = 8094

# Snort alerts
# alert tcp any any -> 10.0.0.1 22 (msg:"SSH attempt"; sid:1000001)
SSH_ALERT = "SSH attempt"

class LogPackets(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'snortlib': snortlib.SnortLib}

    def __init__(self, *args, **kwargs):
        super(LogPackets, self).__init__(*args, **kwargs)

        # Switch MAC HOST <-> Port table
        self.mac_to_port = {}

        # Switch MAC PORT <-> Port number table
        self.port_datapath_to_port = {}
        
        # Datapaths
        self.datapaths = {}

        # Snort conf
        self.snort = kwargs['snortlib']
        self.snort_port = 4
        socket_config = {'unixsock': True}
        self.snort.set_config(socket_config)
        self.snort.start_socket_server()

    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        print('[DEBUG] _dump_alert()')
        msg = ev.msg
        time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print('[%s] alertmsg: %s' % (time, msg.alertmsg[0].decode()))
    
    def disable_port(self, port_no, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        # Get MAC from datapath ports
        hw_addr = datapath.ports[port_no].hw_addr
        print(f'==> Disabling port {port_no} with MAC {hw_addr}')

        config = ofp.OFPPC_PORT_DOWN
        mask = ofp.OFPPC_PORT_DOWN
        advertise = 0
        req = ofp_parser.OFPPortMod(datapath, port_no, hw_addr, config, mask, advertise)
        datapath.send_msg(req)
        return

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        
        # Save datapaths
        self.logger.debug("==> Saving datapath %d" % datapath.id)
        self.datapaths[datapath.id] = datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        
        datapath.send_msg(mod)

    def create_match(self, datapath, in_port, pkt):
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if not eth_pkt:
            return
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ipv4_pkt:
            return
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        
        # We will only add flows for TCP and UDP.
        if tcp_pkt:
            return datapath.ofproto_parser.OFPMatch(
                in_port=in_port,
                eth_src=eth_pkt.src,
                eth_dst=eth_pkt.dst,
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ipv4_pkt.src,
                ipv4_dst=ipv4_pkt.dst,
                ip_proto=6,
                #tcp_src=tcp_pkt.src_port,
                tcp_dst=tcp_pkt.dst_port
            )
        elif udp_pkt:
            return datapath.ofproto_parser.OFPMatch(
                in_port=in_port,
                eth_src=eth_pkt.src,
                eth_dst=eth_pkt.dst,
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ipv4_pkt.src,
                ipv4_dst=ipv4_pkt.dst,
                ip_proto=17,
                #udp_src=udp_pkt.src_port,
                udp_dst=udp_pkt.dst_port
            )

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.debug("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port), parser.OFPActionOutput(self.snort_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            # We will create a match depending on the packet type.
            match = self.create_match(datapath, in_port, pkt)

            if match:
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

        self.store_packet(ev)

    def store_packet(self, ev):
        PACKET_MSG = 'unhandled_packets,switch_id=%d src_mac="%s",src_addr="%s",src_port=%d,dst_mac="%s",dst_addr="%s",dst_port=%d %d'

        pkt = packet.Packet(ev.msg.data)
        
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp) # SSH may sometimes be run using UDP.

        # Ignore IPv6, ICMP and ARP.
        if not ipv4_pkt or not (tcp_pkt or udp_pkt):
            self.logger.debug('received a non-TCP-non-UDP packet')
            return

        dpid = ev.msg.datapath.id
        src_mac = eth_pkt.src
        src_addr = ipv4_pkt.src
        dst_addr = ipv4_pkt.dst
        dst_mac = eth_pkt.dst
        src_port = tcp_pkt.src_port if tcp_pkt else udp_pkt.src_port
        dst_port = tcp_pkt.dst_port if tcp_pkt else udp_pkt.dst_port

        timestamp = int(datetime.datetime.now().timestamp() * 1000000000)
        msg = PACKET_MSG % (dpid, src_mac, src_addr, src_port, dst_mac, dst_addr, dst_port, timestamp)

        #############################
        # Send the packet to Telegraf.
        #############################
        # self.logger.info(msg)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(msg.encode(), (UDP_IP, UDP_PORT))