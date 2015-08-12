# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""

import logging
import struct
import json
import ast
import time
import sys
import inspect
import socket

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller import handler
from ryu.controller.handler import set_ev_cls
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib import addrconv
from ryu.lib import dpid as dpid_lib
from ryu.lib import hub
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import WSGIApplication
from ryu.exception import RyuException
from ryu.exception import OFPUnknownVersion
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from webob import Response

# =============================
#          REST API
# =============================
#
# * test 
# POST /rtt/switch
# POST /rtt/pc
#
# parameter = { "sender" : {"dpid": "0000000000000001", 
#                           "port": 1},
#              "target": {"port": 1,
#                           "vlan": 2,
#                           "mac": "00:01:02:03:04:05",
#                           "ip": "192.168.1.1"}
#              }
#
#
#
ARP = arp.arp.__name__
ARP_REQUEST = arp.ARP_REQUEST
ARP_REPLY = arp.ARP_REPLY

PKT_LIB_PATH = 'ryu.lib.packet'
for modname, moddef in sys.modules.iteritems():
    if not modname.startswith(PKT_LIB_PATH) or not moddef:
        continue
    for (clsname, clsdef, ) in inspect.getmembers(moddef):
        if not inspect.isclass(clsdef):
            continue
        exec 'from %s import %s' % (modname, clsname)


REST_RESULT = 'result'
REST_DETAILS = 'details'
REST_NG = 'failure'

KEY_TYPE = "type"
KEY_SENDER = "sender"
KEY_SENDER_DPID = "dpid"
KEY_SENDER_PORT = "port"
KEY_TARGET = "target"
KEY_TARGET_PORT = "port"
KEY_TARGET_VLAN = "vlan"
KEY_TARGET_IP = "ip"
KEY_TARGET_MAC = "mac"


PKT_INGRESS = "ingress"
PKT_EGRESS = "egress"
SENDER_MAC = "12:11:11:11:11:11"
SENDER_IP =  "192.168.10.10"
VLANID_NONE = 0

WAIT_TIMER = 1  # sec
IDLE_TIMEOUT = 180 # sec

RES_REPORT = "report"
RES_MAX_TIME = "max_time"
RES_MIN_TIME = "min_time"
RES_AVG_TIME = "avg_time"
RES_TRANSMITTED = "transmitted"
RES_PACKET_LOSS = "packet_loss"
RES_RECEIVED = "received"
RES_DETAILS = "details"
RES_PKT_STATE = "state"
RES_PKT_STATE_OK = "OK"
RES_PKT_STATE_LOSS = "LOSS"
RES_PKT_STATE_COMPARE_FAIL = "PKT COMPARE FAIL"
RES_PKT_SIZE = "size"
RES_PKT_TIME = "time"
RES_EXECUTE_STATE = "execute_state"
RES_EXECUTE_STATE_OK = "OK"
RES_EXECUTE_STATE_FAILURE = "FAILURE(%s)"


class NotFoundError(RyuException):
    message = 'Router SW is not connected. : switch_id=%(switch_id)s'


class CommandFailure(RyuException):
    pass



class RestRTTAPI(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(RestRTTAPI, self).__init__(*args, **kwargs)

        # logger configure
        RTTController.set_logger(self.logger)

        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {'waiters': self.waiters}

        mapper = wsgi.mapper
        wsgi.registory['RTTController'] = self.data
        
        self.switch_list = {}

        self._set_mapper(mapper)

    def _set_mapper(self, mapper):
        # For database
        requirements = {}

        path = '/rtt/switch'
        mapper.connect('router', path, controller=RTTController,
                        requirements=requirements,
                        action='test_switch',
                        conditions=dict(method=['POST']))

        path = '/rtt/pc'
        mapper.connect('router', path, controller=RTTController,
                        requirements=requirements,
                        action='test_pc',
                        conditions=dict(method=['POST']))



    @set_ev_cls(ofp_event.EventOFPStateChange,
                [handler.MAIN_DISPATCHER, handler.DEAD_DISPATCHER])
    def dispacher_change(self, ev):
        assert ev.datapath is not None
        if ev.state == handler.MAIN_DISPATCHER:
            self.evnet_ofp_state_change = ev.state
            if ev.datapath.id is not None:
                RTTController.register(ev.datapath)
        elif ev.state == handler.DEAD_DISPATCHER:
            self.evnet_ofp_state_change = ev.state
            if ev.datapath.id is not None:
                RTTController.unregister(ev.datapath)    

    @set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        RTTController.packet_in_handler(ev.msg)
        

    @set_ev_cls([ofp_event.EventOFPFlowStatsReply],handler.MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        # keys: stats reply event classes
        # values: states in which the events should be processed
        pass

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

class RTTController(ControllerBase):
    _SWITCH_LIST = {}
    _LOGGER = None
    _SENDER = None
    _RECV_MSGS = []
    _WAITER = None
    _PKT = None

    def __init__(self, req, link, data, **config):
        super(RTTController, self).__init__(req, link, data, **config)
        self.waiters = data['waiters']

    @classmethod
    def set_sender(cls, sender):
        cls._SENDER = sender

    @classmethod
    def set_pkt(cls, pkt):
        cls._PKT = pkt

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
        cls._SWITCH_LIST[dp.id] = dp
        dpid = {'sw_id': dpid_lib.dpid_to_str(dp.id)}
        cls._LOGGER.info('Register switch.', extra=dpid)

    @classmethod
    def unregister(cls, dp):
        if dp.id in cls._SWITCH_LIST:
            del cls._SWITCH_LIST[dp.id]
            dpid = {'sw_id': dpid_lib.dpid_to_str(dp.id)}
            cls._LOGGER.info('Unregister switch.', extra=dpid)


    @classmethod
    def _compare(cls, data):
        if len(data) == len(cls._PKT[PKT_EGRESS]):
            return True
        return False
    
    @classmethod
    def _wait(cls):
        """ Wait until specific OFP message received
             or timer is exceeded. """
        assert cls._WAITER is None

        cls._WAITER = hub.Event()
        cls._RECV_MSGS = []

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
    def packet_in_handler(cls, msg):
        def _parser_header(data):
            pkt = packet.Packet(msg.data)
            # TODO: Packet library convert to string
            # self.logger.debug('Packet in = %s', str(pkt), self.sw_id)
            header_list = dict((p.protocol_name, p)
                           for p in pkt.protocols if type(p) != str)
            return header_list

        header_list = _parser_header(msg.data)
        if ARP in header_list:
            cls._SENDER.handle_arp(msg, header_list)
        else:
            datapath = msg.datapath
            if cls._SENDER != None and\
                datapath.id == cls._SENDER.get_dpid():
                while not isinstance(cls._WAITER,hub.Event):
                    hub.sleep(1)
                cls._WAITER.set()
                cls._RECV_MSGS.append(msg.data)
        
    def _get_pkt(self, test):
        def __test_pkt_from_json(test):
            test =json.loads(json.dumps(test))
            data = eval('/'.join(test))
            data.serialize()
            return str(data.data)
          # parse 'tests'
        test_pkt = {}
        # parse 'ingress'  
        if PKT_INGRESS not in test:
            raise ValueError('a test requires "%s" field.' % PKT_INGRESS)
        if isinstance(test[PKT_INGRESS], list):
            test_pkt[PKT_INGRESS] = __test_pkt_from_json(test[PKT_INGRESS])                
        else:
            raise ValueError('invalid format: "%s" field' % PKT_INGRESS)
        # parse 'egress' or 'PACKET_IN' or 'table-miss'
        if PKT_EGRESS in test:
            if isinstance(test[PKT_EGRESS], list):
                test_pkt[PKT_EGRESS] = __test_pkt_from_json(
                        test[PKT_EGRESS])
            else:
                raise ValueError('invalid format: "%s" field' % PKT_EGRESS)
        return test_pkt

    @rest_command
    def test_switch(self, req):
        try :
            rest_param = req.body
            ujson_parm = json.loads(rest_param) if rest_param else {}
            parm = ast.literal_eval(json.dumps(ujson_parm))

            sender_port = parm[KEY_SENDER][KEY_SENDER_PORT]
            sender_id = int(parm[KEY_SENDER][KEY_SENDER_DPID],16)
            target_port = parm[KEY_TARGET][KEY_TARGET_PORT]
            target_vlan = parm[KEY_TARGET][KEY_TARGET_VLAN]
            target_mac = parm[KEY_TARGET][KEY_TARGET_MAC]
            target_ip = parm[KEY_TARGET][KEY_TARGET_IP]

            packet = {
                "ingress":["ethernet(dst='%s', src='12:11:11:11:11:11', ethertype=33024)" % (target_mac),
                    "vlan(pcp=3, cfi=0, vid=%d, ethertype=2048)" % (target_vlan),
                    "ipv4(tos=32, proto=1, src='192.168.10.10', dst='%s', ttl=64)" % (target_ip),
                    "icmp(code=0,csum=0,data=echo(data='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL'),type_=8)"
                ],
                "egress":["ethernet(dst='%s', src='12:11:11:11:11:11', ethertype=33024)" % (target_mac),
                    "vlan(pcp=3, cfi=0, vid=%d, ethertype=2048)" % (target_vlan),
                    "ipv4(tos=32, proto=1, src='192.168.10.10', dst='%s', ttl=64)" % (target_ip),
                    "icmp(code=0,csum=0,data=echo(data='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL'),type_=8)"
                ]
            }
            return self._execute_rtt(packet, sender_id, sender_port)

        except NotFoundError as err:
            status = RES_EXECUTE_STATE_FAILURE % str(err)
        except Exception as err:
            msg = "type=%s, msg=%s" % (type(err), str(err))
            status = RES_EXECUTE_STATE_FAILURE % msg

        return {  RES_EXECUTE_STATE: status,
                    RES_MAX_TIME: 0,
                    RES_MIN_TIME: 0,
                    RES_AVG_TIME: 0,
                    RES_RECEIVED: 0,
                    RES_TRANSMITTED: 0,
                    RES_PACKET_LOSS: "100%",
                    RES_DETAILS : []}

    @rest_command
    def test_pc(self, req):
        try :
            rest_param = req.body
            ujson_parm = json.loads(rest_param) if rest_param else {}
            parm = ast.literal_eval(json.dumps(ujson_parm))

            sender_port = parm[KEY_SENDER][KEY_SENDER_PORT]
            sender_id = int(parm[KEY_SENDER][KEY_SENDER_DPID],16)
            target_port = parm[KEY_TARGET][KEY_TARGET_PORT]
            target_vlan = parm[KEY_TARGET][KEY_TARGET_VLAN]
            target_mac = parm[KEY_TARGET][KEY_TARGET_MAC]
            target_ip = parm[KEY_TARGET][KEY_TARGET_IP]

            packet = {
                "ingress":["ethernet(dst='%s', src='12:11:11:11:11:11', ethertype=2048)" % (target_mac),
                    "ipv4(tos=32, proto=1, src='192.168.0.10', dst='%s', ttl=64)" % (target_ip),
                    "icmp(code=0,csum=0,data=echo(data='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL'),type_=8)"
                    ],
                "egress":["ethernet(dst='%s', src='12:11:11:11:11:11', ethertype=2048)" % (target_mac),
                    "ipv4(tos=32, proto=1, src='192.168.0.10', dst='%s', ttl=64)" % (target_ip),
                    "icmp(code=0,csum=0,data=echo(data='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL'),type_=8)"
                    ]
                }

            return self._execute_rtt(packet, sender_id, sender_port)

        except NotFoundError as err:
            status = RES_EXECUTE_STATE_FAILURE % str(err)
        except Exception as err:
            msg = "type=%s, msg=%s" % (type(err), str(err))
            status = RES_EXECUTE_STATE_FAILURE % msg

        return {  RES_EXECUTE_STATE: status,
                    RES_MAX_TIME: 0,
                    RES_MIN_TIME: 0,
                    RES_AVG_TIME: 0,
                    RES_RECEIVED: 0,
                    RES_TRANSMITTED: 0,
                    RES_PACKET_LOSS: "100%",
                    RES_DETAILS : []}


    def _execute_rtt(self, packet, sender_id, sender_port):
        times = 5
        max_time = 0
        min_time = WAIT_TIMER + 1
        avg_time = 0
        transmitted = 0
        received = 0
        result = []
        
        if not self._SWITCH_LIST.has_key(sender_id):
            raise NotFoundError(switch_id=dpid_lib.dpid_to_str(sender_id))
            
        sender = Sender(self._SWITCH_LIST[sender_id], sender_port, self._LOGGER)
        self.set_sender(sender)

        # add flow entry
        sender.add_flow(sender_port)
            
        # transfer packet
        data = self._get_pkt(packet)
        self.set_pkt(data)

        # start rtt 
        for t in range(times):
            start_time = time.time()
            sender.send_packet_out_port(data[PKT_INGRESS], sender_port)
            transmitted = transmitted + 1
            timeout = self._wait()
            rtt = time.time() - start_time

            state = RES_PKT_STATE_OK
            if timeout or not self._compare(self._RECV_MSGS[0]) :
                rtt = -1
                state = RES_PKT_STATE_LOSS
            else :
                max_time = max(max_time, rtt)
                min_time = min(min_time, rtt)

                if t == 0 : avg_time = rtt
                else : avg_time = ( avg_time + rtt ) / 2
                received = received + 1

            result.append({  RES_PKT_STATE: state,
                                RES_PKT_TIME:rtt*1000})


        return {  RES_EXECUTE_STATE: RES_EXECUTE_STATE_OK,
                    RES_MAX_TIME: max_time*1000,
                    RES_MIN_TIME: min_time*1000 if min_time < (WAIT_TIMER+1) else 0,
                    RES_AVG_TIME: avg_time*1000,
                    RES_RECEIVED: received,
                    RES_TRANSMITTED: transmitted,
                    RES_PACKET_LOSS: "%d%%" % (((transmitted - received)/transmitted)*100),
                    RES_DETAILS : result}

class Sender(dict):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self, dp, port, logger):
        super(Sender, self).__init__()
        self.dp = dp
        self.dpid_str = dpid_lib.dpid_to_str(dp.id)
        self.sw_id = {'sw_id': self.dpid_str}
        self.logger = logger
        self.port = port

    def get_dpid(self):
        return self.dp.id

    def add_flow(self, in_port):
        datapath = self.dp
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(in_port=in_port)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod( idle_timeout=IDLE_TIMEOUT ,datapath=datapath, priority=ofproto_v1_3.OFP_DEFAULT_PRIORITY,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def send_packet_out_port(self, data, port):
        """ send a PacketOut message."""
        datapath = self.dp
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        actions = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(
            datapath=self.dp, buffer_id=ofp.OFP_NO_BUFFER,
            data=data, in_port=ofp.OFPP_CONTROLLER, actions=actions)
        datapath.send_msg(out) 

    def handle_arp(self, msg, header_list):
        in_port = self.port
        src_ip = header_list[ARP].src_ip
        dst_ip = header_list[ARP].dst_ip
        srcip = self._ip_addr_ntoa(src_ip)
        dstip = self._ip_addr_ntoa(dst_ip)
        if header_list[ARP].opcode == ARP_REQUEST:
            # ARP request to router port -> send ARP reply
            src_mac = header_list[ARP].src_mac
            dst_mac = SENDER_MAC
            arp_target_mac = dst_mac
            output = in_port
            in_port = self.dp.ofproto.OFPP_CONTROLLER

            self._send_arp(ARP_REPLY, 0,
                                dst_mac, src_mac, dst_ip, src_ip,
                                arp_target_mac, in_port, output)

            log_msg = 'Receive ARP request from [%s] to port [%s].'
            self.logger.info(log_msg, srcip, dstip, extra=self.sw_id)
            self.logger.info('Send ARP reply to [%s]', srcip,
                                 extra=self.sw_id)

    def _send_arp(self, arp_opcode, vlan_id, src_mac, dst_mac,
                 src_ip, dst_ip, arp_target_mac, in_port, output):
            # Generate ARP packet
            if vlan_id != VLANID_NONE:
                ether_proto = eth_er.ETH_TYPE_8021Q
                pcp = 0
                cfi = 0
                vlan_ether = ether.ETH_TYPE_ARP
                v = vlan.vlan(pcp, cfi, vlan_id, vlan_ether)
            else:
                ether_proto = ether.ETH_TYPE_ARP
            hwtype = 1
            arp_proto = ether.ETH_TYPE_IP
            hlen = 6
            plen = 4

            pkt = packet.Packet()
            e = ethernet(dst_mac, src_mac, ether_proto)
            a = arp(hwtype, arp_proto, hlen, plen, arp_opcode,
                    src_mac, src_ip, arp_target_mac, dst_ip)
            pkt.add_protocol(e)
            if vlan_id != VLANID_NONE:
                pkt.add_protocol(v)
            pkt.add_protocol(a)
            pkt.serialize()

            # Send packet out
            self.send_packet_out_port(pkt.data,output)

    def _ip_addr_ntoa(self, ip):
        return socket.inet_ntoa(addrconv.ipv4.text_to_bin(ip))
