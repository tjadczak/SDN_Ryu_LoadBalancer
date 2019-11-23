from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from operator import attrgetter
from ryu.lib import hub
import datetime


class SimpleLoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleLoadBalancer, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.previous_byte_count_sum = [0, 0, 0, 0, 0, 0] #tu zapamietana wartosc przeslanych byteow w poprzedniej sekundzie
        self.current_load = [0, 0, 0, 0, 0, 0] #tu obecny load na danym switchu w Mbps
        self.monitor_thread = hub.spawn(self._monitor)
        self.time_interval = 5 # co ile sekund zbierane statystyki ze switchy

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            self.logger.info("---------------------------------------------------")
            self.logger.info(datetime.datetime.now().strftime("%H:%M:%S"))
            self.logger.info("---------------------------------------------------")
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.time_interval)

    def _request_stats(self, datapath):
        #self.logger.info('Send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        transmited_data = 0
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            #sumowanie przeslanych danych przez kazdy flow
            #stat.byte_count pokazuje ilosc bajtow przeslanych sumarycznie dla danego flowa
            #wiec trzea odjac od poprzedniej probki obecna zeby policzyc przeslane w ciagu sekundy
            transmited_data += stat.byte_count


        self.current_load[ev.msg.datapath.id] = (transmited_data - self.previous_byte_count_sum[ev.msg.datapath.id])*8.0/1000000/self.time_interval 
        self.previous_byte_count_sum[ev.msg.datapath.id] = transmited_data 
        
        self.logger.info("Datapath : %016x load : %10f Mbps", 
                ev.msg.datapath.id, self.current_load[ev.msg.datapath.id])

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
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
            self.logger.info("Received LLDP packet")
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        #self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        #self.mac_to_port[dpid][src] = in_port

        #if dst in self.mac_to_port[dpid]:
        #    out_port = self.mac_to_port[dpid][dst]
        #else:
        #    out_port = ofproto.OFPP_FLOOD
        if (dpid == 1 and in_port == 1): #jesli switch 1 i przyszlo z portu 1(od h1)
            if self.current_load[2] <= self.current_load[3]:
                if self.current_load[2] <= self.current_load[4]:
                    out_port = 2
                    self.logger.info("dp 1 out 2")
                else:
                    out_port = 4
                    self.logger.info("dp 1 out 4")
            else:
                if self.current_load[3] <= self.current_load[4]:
                    out_port = 3
                    self.logger.info("dp 1 out 3")
                else:
                    out_port = 4
                    self.logger.info("dp 1 out 4")
        elif dpid == 1: #jesli switch 1 i przyszlo z innego portu(ktorys z 3 switchy)
            out_port = 1
            self.logger.info("dp 1 out 1")


        elif (dpid == 2 and in_port == 1):
            out_port = 2
        elif (dpid == 3 and in_port == 1):
            out_port = 2
        elif (dpid == 4 and in_port == 1):
            out_port = 2

        elif (dpid == 2 and in_port == 2):
            out_port = 1
        elif (dpid == 3 and in_port == 2):
            out_port = 1
        elif (dpid == 4 and in_port == 2):
            out_port = 1

        if (dpid == 5 and in_port == 4): #jesli switch 5 i przyszlo z portu 4(od h5)
            if self.current_load[2] <= self.current_load[3]:
                if self.current_load[2] <= self.current_load[4]:
                    out_port = 1
                else:
                    out_port = 3
            else:
                if self.current_load[3] <= self.current_load[4]:
                    out_port = 2
                else:
                    out_port = 3
        elif dpid == 5: #jesli switch 5 i przyszlo z innego portu(ktorys z 3 switchy)
            out_port = 4


        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
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


