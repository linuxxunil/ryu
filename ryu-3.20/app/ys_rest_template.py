import logging
import json

from ryu.base import app_manager
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import WSGIApplication
from ryu.controller import ofp_event
from ryu.controller import handler
from ryu.controller.handler import set_ev_cls
from ryu.exception import RyuException
from ryu.exception import OFPUnknownVersion
from ryu.lib import dpid as dpid_lib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.ofproto import ofproto_v1_3
from webob import Response

WAIT_TIMER = 3  # sec

REST_RESULT = 'result'
REST_DETAILS = 'details'
REST_OK = 'success'
REST_NG = 'failure'


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


class RestTemplateAPI(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(RestTemplateAPI, self).__init__(*args, **kwargs)

        # Set Controller
        self.controller = TemplateController
        controller_name = "TemplateController"

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
        


class TemplateController(ControllerBase):
    _SWITCH_LIST = {}
    _LOGGER = None
    _RCV_MSGS = []
    _WAITER = None

    def __init__(self, req, link, data, **config):
        super(TemplateController, self).__init__(req, link, data, **config)
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
            switch = Switch(dp, cls._LOGGER)
            switch.initial(dp)
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


    @rest_command
    def template_get(self, req):
    	return []

    @rest_command
    def template_post(self, req):
    	return []


class Switch(dict):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, dp, logger):
        super(Switch, self).__init__()
        self.dp = dp
        self.dpid_str = dpid_lib.dpid_to_str(dp.id)
        self.sw_id = {'sw_id': self.dpid_str}
        self.logger = logger

        self.mac_to_port = {}

    def initial(self, datapath):
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

    def packet_in_handler(self, ev):
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

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port,extra=self.sw_id)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
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
