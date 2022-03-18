from dataclasses import dataclass

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import ethernet, ether_types, packet, in_proto, udp, ipv4
from ryu.ofproto import ofproto_v1_3
from ryu.utils import hex_array


@dataclass
class UdpServer:
    mac: str
    ip: str
    udp_port: int


class UdpRedirection(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    SERVER1 = UdpServer(mac='00:00:00:00:00:01', ip='10.0.0.1', udp_port=11111)
    SERVER2 = UdpServer(mac='00:00:00:00:00:02', ip='10.0.0.2', udp_port=22222)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = {
            1: {
                self.SERVER1.mac: 1,
                self.SERVER2.mac: 2
            }
        }
        self.current_server = self.SERVER1

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info(f'register datapath: {datapath.id:016x}')
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info(f'unregister datapath: {datapath.id:016x}')
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        self.logger.error(
            f'OFPErrorMsg received: type={ev.msg.type} code={ev.msg.code} message={hex_array(ev.msg.data)}')

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install the table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.warn(f'packet truncated: only {ev.msg.msg_len} of {ev.msg.total_len} bytes')

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = ev.msg.match['in_port']

        pkt = packet.Packet(ev.msg.data)
        pkt_eth = pkt.get_protocols(ethernet.ethernet)[0]

        # ignore lldp packet
        if pkt_eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.logger.info(f'packet_in dpid={datapath.id} src={pkt_eth.src} dst={pkt_eth.dst} in_port={in_port}')

        self.mac_to_port.setdefault(datapath.id, {})
        # learn source MAC
        self.mac_to_port[datapath.id][pkt_eth.src] = in_port

        # redirect UDP packet
        if pkt_eth.ethertype == ether_types.ETH_TYPE_IP:
            pkt_ip = pkt.get_protocol(ipv4.ipv4)

            if pkt_ip.proto == in_proto.IPPROTO_UDP:
                pkt_udp = pkt.get_protocol(udp.udp)
                self.redirect_udp(datapath=datapath,
                                  msg=ev.msg,
                                  priority=1000,
                                  in_port=in_port,
                                  eth_dst=pkt_eth.dst,
                                  eth_src=pkt_eth.src,
                                  udp_dst=pkt_udp.dst_port,
                                  udp_src=pkt_udp.src_port)
                return

        if pkt_eth.dst in self.mac_to_port[datapath.id]:
            # decide out port if destination MAC is known
            out_port = self.mac_to_port[datapath.id][pkt_eth.dst]
        else:
            # flood if destination is unknown
            out_port = ofproto.OFPP_FLOOD

        # used with a packet_out message to specify a switch port to send the packet out of
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            # destination MAC has been learned
            match = parser.OFPMatch(in_port=in_port, eth_dst=pkt_eth.dst, eth_src=pkt_eth.src)
            # verify if we have a valid buffer_id, if yes avoid sending both flow_mod & packet_out
            if ev.msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, ev.msg.buffer_id)
                return
            else:
                # self.add_flow(datapath, 1, match, actions)
                pass

        # forward other packet
        self.send_packet_out(msg=ev.msg, actions=actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, **kwargs):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                buffer_id=buffer_id if buffer_id else ofproto.OFP_NO_BUFFER,
                                priority=priority,
                                match=match,
                                instructions=inst,
                                **kwargs)

        self.logger.info(
            f'flow_mod dpid={datapath.id} priority={priority} match={match} actions={actions} buffer_id={buffer_id}')
        datapath.send_msg(mod)

    def send_packet_out(self, msg, actions):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None

        # construct packet_out message and send
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)

        self.logger.info(f'packet_out dpid={datapath.id} in_port={in_port}')
        datapath.send_msg(out)

    def redirect_udp(self, datapath, msg, priority, in_port, eth_dst, eth_src, udp_dst, udp_src):
        parser = datapath.ofproto_parser

        server_port = self.mac_to_port[datapath.id][self.current_server.mac]

        # route to current server
        match = parser.OFPMatch(in_port=in_port,
                                eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_dst=self.SERVER1.ip,
                                ip_proto=in_proto.IPPROTO_UDP)

        actions = [
            parser.OFPActionSetField(eth_dst=self.current_server.mac),
            parser.OFPActionSetField(ipv4_dst=self.current_server.ip),
            parser.OFPActionSetField(udp_dst=self.current_server.udp_port),
            parser.OFPActionOutput(server_port)
        ]

        self.logger.info('adding udp redirection flow')
        self.add_flow(datapath, priority, match, actions, hard_timeout=2)

        # reverse route
        reverse_match = parser.OFPMatch(in_port=server_port,
                                        eth_type=ether_types.ETH_TYPE_IP,
                                        eth_dst=eth_src,
                                        ipv4_src=self.current_server.ip,
                                        ip_proto=in_proto.IPPROTO_UDP)

        reverse_actions = [
            parser.OFPActionSetField(eth_src=self.SERVER1.mac),
            parser.OFPActionSetField(ipv4_src=self.SERVER1.ip),
            parser.OFPActionSetField(udp_src=self.SERVER1.udp_port),
            parser.OFPActionOutput(in_port)
        ]

        self.logger.info('adding reverse udp redirection flow')
        self.add_flow(datapath, priority, reverse_match, reverse_actions, hard_timeout=0)

        if eth_src == self.SERVER1.mac or eth_src == self.SERVER2.mac:
            self.send_packet_out(msg, reverse_actions)
        else:
            self.send_packet_out(msg, actions)

        self.current_server = self.SERVER2
