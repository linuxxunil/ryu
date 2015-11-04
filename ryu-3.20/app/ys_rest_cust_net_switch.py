""" network topology :



    +------------+           +------------+
    |    ISP1    |           |   ISP2     |     
    +------------+           +------------+                     
                 \          /
                +------------+
                | controller |     
                +------------+
                 /          \  
    +------------+          +------------+
    |  Staff     |          |  Customer  |     
    +------------+          +------------+

"""

import logging
import json

from ryu.base import app_manager
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import WSGIApplication
from ryu.controller import ofp_event
from ryu.controller import handler
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.exception import RyuException
from ryu.exception import OFPUnknownVersion
from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from webob import Response



WAIT_TIMER = 3  # sec

REST_RESULT = 'result'
REST_DETAILS = 'details'
REST_OK = 'success'
REST_NG = 'failure'

# Decalre Hard timeout
HARD_TIMEOUT = 600

# Decalre Priority Value
PRI_LAN     = 0x8000
PRI_DEF_NETWORK = 0x8000 - 1
PRI_CUST_NETWORK = 0x8000 - 2
PRI_ARP     = 2
PRI_DHCP    = 1
PRI_MISS    = 0

# Declare Cookie Value
COOKIE_LAN  = 1
COOKIE_DEF_NETWORK = 2
COOKIE_CUST_NETWORK = 3
COOKIE_ARP  = 4
COOKIE_DHCP = 5
COOKIE_MISS = 6




class NotFoundError(RyuException):
    message = 'Router SW is not connected. : switch_id=%(switch_id)s'

# REST command template
def rest_command(func):
    def _rest_command(*args, **kwargs):
        try:
            msg = func(*args, **kwargs)
            return Response(content_type='application/json',
                            body=json.dumps(msg))

        except SyntaxError as e:
            status = 400
            details = e.msg
        except (ValueError, NameError) as e:
            status = 400
            details = e.message

        except NotFoundError as msg:
            status = 404
            details = str(msg)

        msg = {REST_RESULT: REST_NG,
               REST_DETAILS: details}
        return Response(status=status, body=json.dumps(msg))

    return _rest_command


class RestCustNetSwitchAPI(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(RestCustNetSwitchAPI, self).__init__(*args, **kwargs)

        # Set Controller
        self.controller = CustNetSwitchController
        controller_name = "CustNetSwitchController"

        # logger configure
        self.controller.set_logger(self.logger)

        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {'waiters': self.waiters}

        mapper = wsgi.mapper
        wsgi.registory[controller_name] = self.data
        
        self.switch_list = {}

        self._set_uri_mapper(mapper)

    def _set_uri_mapper(self, mapper):
        # For database
        requirements = {}


        path = '/template/post'
        mapper.connect('template', path, controller=self.controller,
                        requirements=requirements,
                        action='template_post',
                        conditions=dict(method=['POST']))

        path = '/template/get'
        mapper.connect('template', path, controller=self.controller,
                        requirements=requirements,
                        action='template_get',
                        conditions=dict(method=['GET']))



    @set_ev_cls(ofp_event.EventOFPStateChange,
                [handler.MAIN_DISPATCHER, handler.DEAD_DISPATCHER])
    def dispacher_change(self, ev):
        assert ev.datapath is not None
        if ev.state == handler.MAIN_DISPATCHER:
            self.evnet_ofp_state_change = ev.state
            if ev.datapath.id is not None:
                self.controller.register(ev.datapath)
        elif ev.state == handler.DEAD_DISPATCHER:
            self.evnet_ofp_state_change = ev.state
            if ev.datapath.id is not None:
                self.controller.unregister(ev.datapath)    

    @set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.controller.packet_in_handler(ev)
        


class CustNetSwitchController(ControllerBase):
    _SWITCH_LIST = {}
    _LOGGER = None
    _RCV_MSGS = []
    _WAITER = None

    def __init__(self, req, link, data, **config):
        super(CustNetSwitchController, self).__init__(req, link, data, **config)
        self.waiters = data['waiters']

    @classmethod
    def set_logger(cls, logger):
        cls._LOGGER = logger
        cls._LOGGER.propagate = False
        hdlr = logging.StreamHandler()
        fmt_str = '[RT][%(levelname)s] switch_id=%(sw_id)s: %(message)s'
        hdlr.setFormatter(logging.Formatter(fmt_str))
        cls._LOGGER.addHandler(hdlr)

    @classmethod
    def register(cls, dp):
        dpid = {'sw_id': dpid_lib.dpid_to_str(dp.id)}
        try:
            switch = Switch_13(dp, cls._LOGGER)
        except OFPUnknownVersion as message:
            cls._LOGGER.error(str(message), extra=dpid)
            return
        cls._SWITCH_LIST.setdefault(dp.id, switch)
        cls._LOGGER.info('Join as switch.', extra=dpid)

    @classmethod
    def unregister(cls, dp):
        if dp.id in cls._SWITCH_LIST:
            del cls._SWITCH_LIST[dp.id]
            dpid = {'sw_id': dpid_lib.dpid_to_str(dp.id)}
            cls._LOGGER.info('Unregister switch.', extra=dpid)
           
    @classmethod
    def _wait(cls):
        """ Wait until specific OFP message received
             or timer is exceeded. """
        assert cls._WAITER is None

        cls._WAITER = hub.Event()
        cls._RCV_MSGS = []

        timeout = False
        timer = hub.Timeout(WAIT_TIMER)
        try:
            cls._WAITER.wait()
        except hub.Timeout as t:
            if t is not timer:
                raise Exception('Internal error. Not my timeout.')
            timeout = True
        finally:
            timer.cancel()
        cls._WAITER = None
        return timeout

    @classmethod
    def _get_switch(cls, ev):
        msg = ev.msg
        dp_id = msg.datapath.id
        if dp_id in cls._SWITCH_LIST:
            return cls._SWITCH_LIST[dp_id]
        return None

    @classmethod
    def packet_in_handler(cls, ev):
    	switch = cls._get_switch(ev)
        if switch != None: 
            switch.packet_in_handler(ev)


class Switch_13(dict):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, dp, logger):
        super(Switch_13, self).__init__()
        self.dp = dp
        self.dpid_str = dpid_lib.dpid_to_str(dp.id)
        self.sw_id = {'sw_id': self.dpid_str}
        self.logger = logger
        self.ofctl = ofctl_v1_3
        self.customer_list = {"00:00:00:00:04:00": {"gw": "00:00:00:00:02:00", "port": 2}}
        self._initial()
    

    def _get_db_default_network(self):
        return {"name": "isp1", "mac": "00:00:00:00:01:00", "port": 1}

    def _get_db_lan(self):
        return ["192.168.0.0/255.255.0.0"]

    def _get_db_customer(self, mac):
        keys = self.customer_list.keys()
        if mac in keys:
            return True, self.customer_list[mac]
        return False, 0

    def _add_flowentry(self, priority, cookie, match, actions, buffer_id=None, hard_timeout=0):
        ofproto = self.dp.ofproto
        parser = self.dp.ofproto_parser

        _match = self.ofctl.to_match(self.dp, match)
        _inst = self.ofctl.to_actions(self.dp, actions)

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=self.dp, buffer_id=buffer_id,
                                    priority=priority, cookie=cookie,
                                    hard_timeout=hard_timeout,
                                    match=_match, instructions=_inst)
        else:
            mod = parser.OFPFlowMod(datapath=self.dp, 
                                    priority=priority, cookie=cookie,
                                    hard_timeout=hard_timeout,
                                    match=_match, instructions=_inst)
        self.dp.send_msg(mod)

    def _add_lan_flowentry(self):
        ofproto = self.dp.ofproto
        priority = PRI_LAN
        cookie = COOKIE_LAN

        lans = self._get_db_lan()
        actions = [{"type": "OUTPUT", "port": ofproto.OFPP_NORMAL}]
        for lan in lans:
            match = {"eth_type": 2048, "nw_src": lan, "nw_dst": lan}
            self._add_flowentry(priority, cookie, match, actions)

    def _add_arp_flowentry(self):
        ofproto = self.dp.ofproto
        priority = PRI_ARP
        cookie = COOKIE_ARP

        match = {"eth_type": 2054}
        
        actions = [{"type": "OUTPUT", "port": ofproto.OFPP_NORMAL}]
        
        self._add_flowentry(priority, cookie, match, actions)

    def _add_default_network_flowentry(self):
        ofproto = self.dp.ofproto
        priority = PRI_DEF_NETWORK
        cookie = COOKIE_DEF_NETWORK

        default_net = self._get_db_default_network()

        match = {"eth_src": default_net["mac"]}
        actions = [{"type": "OUTPUT", "port": ofproto.OFPP_NORMAL}]
        self._add_flowentry(priority, cookie, match, actions)

        match = {"eth_dst": default_net["mac"]}
        self._add_flowentry(priority, cookie, match, actions)

    def _add_dhcp_flowentry(self):
        ofproto = self.dp.ofproto
        priority = PRI_DHCP
        cookie = COOKIE_DHCP

        match = {"eth_dst": "FF:FF:FF:FF:FF:FF", "eth_type": 2048, "ipv4_src": "0.0.0.0"}
        
        actions = [{"type": "OUTPUT", "port": ofproto.OFPP_CONTROLLER}]
        
        self._add_flowentry(priority, cookie, match, actions)

    def _add_miss_flowentry(self):
        ofproto = self.dp.ofproto
        priority = PRI_MISS
        cookie = COOKIE_MISS
        match = {}
        actions = []
        
        self._add_flowentry(priority, cookie, match, actions)

    def _add_customer_flowentry(self, cust_mac, gw_mac, cust_port, gw_port):
        ofproto = self.dp.ofproto
        priority = PRI_CUST_NETWORK
        cookie = COOKIE_CUST_NETWORK

        match = {"eth_src": cust_mac, "eth_dst": gw_mac}
        actions = [{"type": "OUTPUT", "port": gw_port}]
        self._add_flowentry(priority, cookie, match, actions, hard_timeout=HARD_TIMEOUT)

        match = {"eth_src": gw_mac, "eth_dst": cust_mac}
        actions = [{"type": "OUTPUT", "port": cust_port}]
        self._add_flowentry(priority, cookie, match, actions, hard_timeout=HARD_TIMEOUT)

    def _send_packet_to_output(self, in_port, out_port, buffer_id, data):
        parser = self.dp.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)]

        out = parser.OFPPacketOut(datapath=self.dp, buffer_id=buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        self.dp.send_msg(out)


    def _initial(self):
        self._add_lan_flowentry()
        self._add_arp_flowentry()
        self._add_dhcp_flowentry()
        self._add_default_network_flowentry()
        self._add_miss_flowentry()
   

    def packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        buffer_id = msg.buffer_id
        in_port = msg.match['in_port']
        ofproto = self.dp.ofproto
        parser = self.dp.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        mac_src = eth.src

        status, cust_info = self._get_db_customer(mac_src)
        if status :
            self._add_customer_flowentry(mac_src, cust_info["gw"], in_port, cust_info["port"])
            out_port = cust_info["port"]
        else :
            out_port = self._get_db_default_network()["port"]

        data = None
        if buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        self._send_packet_to_output(in_port, out_port, buffer_id, data)



        