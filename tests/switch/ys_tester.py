# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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

import binascii
import inspect
import json
import logging
import math
import netaddr
import os
import signal
import sys
import time
import traceback
import threading
from random import randint

from ryu import cfg

# import all packet libraries.
PKT_LIB_PATH = 'ryu.lib.packet'
for modname, moddef in sys.modules.iteritems():
    if not modname.startswith(PKT_LIB_PATH) or not moddef:
        continue
    for (clsname, clsdef, ) in inspect.getmembers(moddef):
        if not inspect.isclass(clsdef):
            continue
        exec 'from %s import %s' % (modname, clsname)

from ryu.base import app_manager
from ryu.controller import handler
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.exception import RyuException
from ryu.lib import dpid as dpid_lib
from ryu.lib import hub
from ryu.lib import stringify
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_protocol

from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto import ofproto_v1_5
from ryu.tests.switch import ys_event as rest_event
from ryu.lib import ofctl_v1_0
from ryu.lib import ofctl_v1_2
from ryu.lib import ofctl_v1_3


""" Required test network:

                      +-------------------+
           +----------|     target sw     | The switch to be tested
           |          +-------------------+
    +------------+      (1)   (2)   (3)
    | controller |       |     |     |
    +------------+      (1)   (2)   (3)
           |          +-------------------+
           +----------|     tester sw     | OpenFlow Switch
                      +-------------------+

      (X) : port number

    Tests send a packet from port 1 of the tester sw.
    If the packet matched with a flow entry of the target sw,
     the target sw resends the packet from port 2 (or the port which
     connected with the controller), according to the flow entry.
    Then the tester sw receives the packet and sends a PacketIn message.
    If the packet did not match, the target sw drops the packet.

    If you want to use the other port number which differ from above chart,
    you can specify the port number in the options when this tool is started.
    For details of this options, please refer to the Help command.
    Also, if you describe the name of an option argument
    (e.g. "target_send_port_1") in test files,
    this tool sets the argument value in the port number.

        e.g.)
            "OFPActionOutput":{
                "port":"target_send_port_1"
            }

"""


CONF = cfg.CONF


# Default settings.
INTERVAL = 1  # sec
WAIT_TIMER = 3  # sec
CONTINUOUS_THREAD_INTVL = float(0.01)  # sec
CONTINUOUS_PROGRESS_SPAN = 3  # sec
TARGET_PRIORITY = ofproto_v1_3.OFP_DEFAULT_PRIORITY
TESTER_PRIORITY = ofproto_v1_3.OFP_DEFAULT_PRIORITY + 11
THROUGHPUT_PRIORITY = ofproto_v1_3.OFP_DEFAULT_PRIORITY + 1
THROUGHPUT_COOKIE = THROUGHPUT_PRIORITY
THROUGHPUT_THRESHOLD = float(0.10)  # expected throughput plus/minus 10 %

# Default settings for 'ingress: packets'
DEFAULT_DURATION_TIME = 30
DEFAULT_PKTPS = 1000

# Test file format.
KEY_DESC = 'description'
KEY_PREREQ = 'prerequisite'
KEY_FLOW = 'OFPFlowMod'
KEY_METER = 'OFPMeterMod'
KEY_GROUP = 'OFPGroupMod'
KEY_TESTS = 'tests'
KEY_INGRESS = 'ingress'
KEY_EGRESS = 'egress'
KEY_PKT_IN = 'PACKET_IN'
KEY_TBL_MISS = 'table-miss'
KEY_PACKETS = 'packets'
KEY_DATA = 'data'
KEY_KBPS = 'kbps'
KEY_PKTPS = 'pktps'
KEY_DURATION_TIME = 'duration_time'
KEY_THROUGHPUT = 'throughput'
KEY_MATCH = 'OFPMatch'

# Test state.
STATE_INIT_FLOW = 0
STATE_FLOW_INSTALL = 1
STATE_FLOW_EXIST_CHK = 2
STATE_TARGET_PKT_COUNT = 3
STATE_TESTER_PKT_COUNT = 4
STATE_FLOW_MATCH_CHK = 5
STATE_NO_PKTIN_REASON = 6
STATE_GET_MATCH_COUNT = 7
STATE_SEND_BARRIER = 8
STATE_FLOW_UNMATCH_CHK = 9
STATE_INIT_METER = 10
STATE_METER_INSTALL = 11
STATE_METER_EXIST_CHK = 12
STATE_INIT_THROUGHPUT_FLOW = 13
STATE_THROUGHPUT_FLOW_INSTALL = 14
STATE_THROUGHPUT_FLOW_EXIST_CHK = 15
STATE_GET_THROUGHPUT = 16
STATE_THROUGHPUT_CHK = 17
STATE_INIT_GROUP = 18
STATE_GROUP_INSTALL = 19
STATE_GROUP_EXIST_CHK = 20
STATE_DISCONNECTED = 99
STATE_TESTER_FLOW_INSTALL = 21
STATE_TARGET_FLOWS = 22
STATE_TESTER_FLOWS = 23
STATE_GET_PORT_DESC = 24
STATE_TARGET_FLOW_COUNT_CHK = 25

STATE_STR = {
    STATE_INIT_FLOW : "FLOW INITIALIZE",
    STATE_FLOW_INSTALL : "FLOW INSTALL",
    STATE_FLOW_EXIST_CHK : "FLOW EXIST CHK",
    STATE_TARGET_PKT_COUNT : "TARGET PACKET COUNT",
    STATE_TESTER_PKT_COUNT : "TASTER PACKET COUNT",
    STATE_FLOW_MATCH_CHK : "FLOW MATCH CHK",
    STATE_NO_PKTIN_REASON : "NO PACKET IN REASON",
    STATE_GET_MATCH_COUNT : "GET MATCH COUNT",
    STATE_SEND_BARRIER : "SEND BARRIER",
    STATE_FLOW_UNMATCH_CHK : "FLOW UNMATCH CHECK",
    STATE_INIT_METER : "INIT METER",
    STATE_METER_INSTALL : "METER INSTALL",
    STATE_METER_EXIST_CHK : "METER EXIST CHECK",
    STATE_INIT_THROUGHPUT_FLOW : "INIT THROUGHPUT FLOW",
    STATE_THROUGHPUT_FLOW_INSTALL : "THROUGHPUT FLOW INSTALL",
    STATE_THROUGHPUT_FLOW_EXIST_CHK : "THROUGHPUT FLOW EXIST CHECK",
    STATE_GET_THROUGHPUT : "GET THROUGHPUT",
    STATE_THROUGHPUT_CHK : "THROUGHPUT CHECK",
    STATE_INIT_GROUP : "INIT GROUP",
    STATE_GROUP_INSTALL : "GROUP INSTALL",
    STATE_GROUP_EXIST_CHK : "GROUP EXIST CHECK",
    STATE_DISCONNECTED : "DISCONNECTED",
    STATE_TARGET_FLOWS : "TARGET FLOWS",
    STATE_TESTER_FLOWS : "TESTER FLOWS",
    STATE_GET_PORT_DESC : "GET PORT DESC",
    STATE_TARGET_FLOW_COUNT_CHK: "TARGET FLOW COUNT CHECK"
}

# Thread state
THREAD_STATE_READY = 0
THREAD_STATE_START_SUCEESS = 1
THREAD_STATE_START_FAILURE = 2
THREAD_STATE_RUNNING = 3
THREAD_STATE_TEST_PATTERN_ERROR = 4
THREAD_STATE_REGISTER_DPID_ERROR = 5

THREAD_STATE_STR = {
    THREAD_STATE_READY: "Thread is ready.",
    THREAD_STATE_START_SUCEESS: "Thread start success.",
    THREAD_STATE_START_FAILURE: "Thread start failure.",
    THREAD_STATE_RUNNING: "Thread is running.",
    THREAD_STATE_TEST_PATTERN_ERROR: "Test script format is error.",
    THREAD_STATE_REGISTER_DPID_ERROR: "DPID register error."
}

# Test
RESULT_EXECUTE_STATE = "execute_state"
RESULT_EXECUTE_DESC = "execute_description"
RESULT_TARGET_DPID = "target_dpid"
RESULT_TEST_DESC = "test_description"
RESULT_REPORT = "report"
RESULT_REPORT_STATUS = "status"
RESULT_REPORT_TEST_REASON = "test_reason"
RESULT_REPORT_TEST_ITEM = "test_item"
RESULT_REPORT_TEST_STATE = "teste_state"
RESULT_REPORT_BEFORE_PORT_STATE = "before_ports_state"
RESULT_REPORT_AFTER_PORT_STATE = "after_ports_state"
RESULT_REPORT_EXPECTED_FLOW = "expected_flow"
RESULT_REPORT_REAL_FLOW = "real_flow"
RESULT_REPORT_PORT_LINK_STATE = "port_link_state"
RESULT_REPORT_SEND_PORT = "send_port"
RESULT_REPORT_OPERATING = "operating"
RESULT_REPORT_CHECK_SEND_PORT = "check_send_port"
RESULT_REPORT_SW_INFO = "switch_info"

RESULT_OK = "OK"
RESULT_ERROR = "ERROR"

# by jesse :
TEST_ITEM_ERROR = 'Test content format error (%(detail)s)'


# target
SW_TARGET = 0
SW_TESTER = 1

# Test port
TESTER_SEND_PORT   = "tester_send_port"
TESTER_RECV_PORT_1 = "tester_recv_port_1"
TESTER_RECV_PORT_2 = "tester_recv_port_2"
TARGET_RECV_PORT   = "target_recv_port"
TARGET_SEND_PORT_1 = "target_send_port_1"
TARGET_SEND_PORT_2 = "target_send_port_2"

# Test result details.
FAILURE = 0
ERROR = 1
TIMEOUT = 2
RCV_ERR = 3

ERR_MSG = {STATE_INIT_FLOW:
            {TIMEOUT: 'Failed to initialize flow tables: barrier request timeout.',
            RCV_ERR: 'Failed to initialize flow tables: %(err_msg)s'},
        STATE_INIT_THROUGHPUT_FLOW:
            {TIMEOUT: 'Failed to initialize flow tables of tester_sw: '
                 'barrier request timeout.',
            RCV_ERR: 'Failed to initialize flow tables of tester_sw: '
                 '%(err_msg)s'},
        STATE_FLOW_INSTALL:
            {TIMEOUT: 'Failed to add flows: barrier request timeout.',
            RCV_ERR: 'Failed to add flows: %(err_msg)s'},
        STATE_THROUGHPUT_FLOW_INSTALL:
            {TIMEOUT: 'Failed to add flows to tester_sw: barrier request timeout.',
            RCV_ERR: 'Failed to add flows to tester_sw: %(err_msg)s'},
        STATE_METER_INSTALL:
            {TIMEOUT: 'Failed to add meters: barrier request timeout.',
            RCV_ERR: 'Failed to add meters: %(err_msg)s'},
        STATE_GROUP_INSTALL:
            {TIMEOUT: 'Failed to add groups: barrier request timeout.',
            RCV_ERR: 'Failed to add groups: %(err_msg)s'},
        STATE_FLOW_EXIST_CHK:
            {FAILURE: 'Added incorrect flows: %(flows)s',
            TIMEOUT: 'Failed to add flows: flow stats request timeout.',
            RCV_ERR: 'Failed to add flows: %(err_msg)s'},
        STATE_METER_EXIST_CHK:
            {FAILURE: 'Added incorrect meters: %(meters)s',
            TIMEOUT: 'Failed to add meters: meter config stats request timeout.',
            RCV_ERR: 'Failed to add meters: %(err_msg)s'},
        STATE_GROUP_EXIST_CHK:
            {FAILURE: 'Added incorrect groups: %(groups)s',
            TIMEOUT: 'Failed to add groups: group desc stats request timeout.',
            RCV_ERR: 'Failed to add groups: %(err_msg)s'},
        STATE_TARGET_PKT_COUNT:
            {TIMEOUT: 'Failed to request port stats from target: request timeout.',
            RCV_ERR: 'Failed to request port stats from target: %(err_msg)s'},
        STATE_TESTER_PKT_COUNT:
            {TIMEOUT: 'Failed to request port stats from tester: request timeout.',
            RCV_ERR: 'Failed to request port stats from tester: %(err_msg)s'},
        STATE_FLOW_MATCH_CHK:
            {FAILURE: 'Received incorrect %(pkt_type)s: %(detail)s',
            TIMEOUT: '',  # for check no packet-in reason.
            RCV_ERR: 'Failed to send packet: %(err_msg)s'},
        STATE_NO_PKTIN_REASON:
            {FAILURE: 'Receiving timeout: %(detail)s'},
            STATE_GET_MATCH_COUNT:
            {TIMEOUT: 'Failed to request table stats: request timeout.',
            RCV_ERR: 'Failed to request table stats: %(err_msg)s'},
        STATE_SEND_BARRIER:
            {TIMEOUT: 'Failed to send packet: barrier request timeout.',
            RCV_ERR: 'Failed to send packet: %(err_msg)s'},
        STATE_FLOW_UNMATCH_CHK:
            {FAILURE: 'Table-miss error: increment in matched_count.',
            ERROR: 'Table-miss error: no change in lookup_count.',
            TIMEOUT: 'Failed to request table stats: request timeout.',
            RCV_ERR: 'Failed to request table stats: %(err_msg)s'},
        STATE_THROUGHPUT_FLOW_EXIST_CHK:
            {FAILURE: 'Added incorrect flows to tester_sw: %(flows)s',
            TIMEOUT: 'Failed to add flows to tester_sw: '
                 'flow stats request timeout.',
            RCV_ERR: 'Failed to add flows to tester_sw: %(err_msg)s'},
        STATE_GET_THROUGHPUT:
            {TIMEOUT: 'Failed to request flow stats: request timeout.',
            RCV_ERR: 'Failed to request flow stats: %(err_msg)s'},
        STATE_THROUGHPUT_CHK:
            {FAILURE: 'Received unexpected throughput: %(detail)s'},
        STATE_DISCONNECTED:
            {ERROR: 'Disconnected from switch'},
        STATE_GET_PORT_DESC:
            {ERROR: 'Failed to port do not links: %(detail)s',
            TIMEOUT: 'Failed to get port stats: request timeout.'},
        STATE_TARGET_FLOW_COUNT_CHK:
            {FAILURE: ' %(detail)s: Byte count of flow entry is not increment'}}

#ERR_MSG = 'OFPErrorMsg[type=0x%02x, code=0x%02x]'




class TestMessageBase(RyuException):
    def __init__(self, state, message_type, **argv):
        self.state = state
        self.message_type = message_type
        msg = ERR_MSG[state][message_type] % argv
        super(TestMessageBase, self).__init__(msg=msg)


class TestFailure(TestMessageBase):
    def __init__(self, state, **argv):
        super(TestFailure, self).__init__(state, FAILURE, **argv)


class TestTimeout(TestMessageBase):
    def __init__(self, state):
        super(TestTimeout, self).__init__(state, TIMEOUT)


class TestReceiveError(TestMessageBase):
    def __init__(self, state, err_msg, ofp_ver):
        if ofp_ver == ofproto_v1_3.OFP_VERSION :
            self.ofproto = ofproto_v1_3
        elif ofp_ver == ofproto_v1_4.OFP_VERSION :    
            pass
        elif ofp_ver == ofproto_v1_5.OFP_VERSION :    
            pass

        _type = self.ofproto.OFP_ERR_TYPE_STR[err_msg.type]
        _code = _type[err_msg.code]

        argv = {'err_msg': "OFPErrorMsg[type=%s(0x%02x), code=%s(0x%02x)]" 
                % (_type["type"], err_msg.type,
                   _code, err_msg.code)}
        
        super(TestReceiveError, self).__init__(state, RCV_ERR, **argv)

    #def __str__(self):
    #    code = self.ofproto.OFP_ERR_TYPE_STR[self.err_type]
    #    return "err_type: %s(%s), err_code: %s(%s)" % \
    #            (code["type"], self.err_type, code[self.err_code] , self.err_code)

class TestError(TestMessageBase):
    def __init__(self, state, **argv):
        super(TestError, self).__init__(state, ERROR, **argv)


class RegisterException(Exception):

    def __init__(self, dpid):
        super(RegisterException, self).__init__()
        self.dpid = dpid

class OfTester(app_manager.RyuApp):
    """ OpenFlow Switch Tester. """ 

    def __init__(self, *args, **kwargs):
        super(OfTester, self).__init__(*args, **kwargs)
        self.name = 'oftester'
    
        self._set_logger()
        self.__init_base()
        self.connected_list = {}  # Save what swtiches is connected to the controller
        self.test_thread_state = THREAD_STATE_READY
        self.test_thread = None

    def __init_base(self):
        self.evnet_ofp_state_change = None
        self.state = STATE_INIT_FLOW
        self.sw_waiter = None
        self.waiter = None
        self.send_msg_xids = []
        self.rcv_msgs = []
        self.ingress_event = None
        self.ingress_threads = []
        self.thread_msg = None

        self.target_dpid = ""
        self.tester_dpid = ""
        self.description = ""
        self.test_report = []  # test log

    def __init(self, req) :
        self.logger.info('--- Test Initialize ---')
        self.__init_base()
    
        self.target_dpid = req.target_dpid
        self.target_recv_port =  req.target_recv_port
        self.target_send_port_1 = req.target_send_port_1
        self.target_send_port_2 = req.target_send_port_2
            
        self.tester_dpid = req.tester_dpid
        self.tester_send_port = req.tester_send_port
        self.tester_recv_port_1 = req.tester_recv_port_1
        self.tester_recv_port_2 = req.tester_recv_port_2

        self.port_map = {
            self.target_recv_port  : TARGET_RECV_PORT,
            self.target_send_port_1: TARGET_SEND_PORT_1,
            self.target_send_port_2: TARGET_SEND_PORT_2,
            self.tester_send_port  : TESTER_SEND_PORT,
            self.tester_recv_port_1: TESTER_RECV_PORT_1,
            self.tester_recv_port_2: TESTER_RECV_PORT_2   
        }

        self.map_port = {
            TARGET_RECV_PORT  : self.target_recv_port,
            TARGET_SEND_PORT_1: self.target_send_port_1,
            TARGET_SEND_PORT_2: self.target_send_port_2,
            TESTER_SEND_PORT  : self.tester_send_port,
            TESTER_RECV_PORT_1: self.tester_recv_port_1,
            TESTER_RECV_PORT_2: self.tester_recv_port_2   
        }

        self.logger.info('target_dpid=%s',
                        dpid_lib.dpid_to_str(self.target_dpid))

        self.logger.info('tester_dpid=%s',
                        dpid_lib.dpid_to_str(self.tester_dpid))

        ofctl_map = {
            "openflow10": ofctl_v1_0,
            "openflow12": ofctl_v1_2,
            "openflow13": ofctl_v1_3,
            "openflow14": None,
            "openflow15": None
        }

        target_opt = req.target_version
        self.logger.info('target_ofp_version=%s', target_opt)
        OfTester.target_ver = self._get_version(target_opt)
        self.target_ofctl = ofctl_map[target_opt.lower()]
        
        tester_opt = req.tester_version
        self.logger.info('tester_ofp_version=%s', tester_opt)
        OfTester.tester_ver = self._get_version(tester_opt)
        self.tester_ofctl = ofctl_map[tester_opt.lower()]
          
        # set app_supported_versions later.
        ofproto_protocol.set_app_supported_versions(
                  [OfTester.target_ver, OfTester.tester_ver])

        self.target_sw = OpenFlowSw(DummyDatapath(), self.logger, req)
        self.tester_sw = OpenFlowSw(DummyDatapath(), self.logger, req)


        self._unregister_sw()
        if self.connected_list.has_key(self.target_dpid):
            dp = self.connected_list[self.target_dpid]
            if self._register_sw(dp) == False:
                raise RegisterException(self.target_dpid)
        else:
            raise RegisterException(self.target_dpid)


        if self.connected_list.has_key(self.tester_dpid):
            dp = self.connected_list[self.tester_dpid]
            if self._register_sw(dp) == False:
                raise RegisterException(self.tester_dpid)
        else:
            raise RegisterException(self.tester_dpid)            
            
        self.logger.info('--- Test Initialize End ---')


    def _get_version(self, opt):
        vers = {
            'openflow13': ofproto_v1_3.OFP_VERSION,
            'openflow14': ofproto_v1_4.OFP_VERSION,
            'openflow15': ofproto_v1_5.OFP_VERSION
        }
        ver = vers.get(opt.lower())
        if ver is None:
            self.logger.error(
                '%s is not supported. '
                'Supported versions are openflow13, '
                'openflow14 and openflow15.',
                opt)
            self._test_end()
        return ver

    def _get_version_desc(self, opt):
        vers = {
            ofproto_v1_3.OFP_VERSION: 'openflow13',
            ofproto_v1_4.OFP_VERSION: 'openflow14',
            ofproto_v1_5.OFP_VERSION: 'openflow15'
        }
        return ves[opt]

    def _set_logger(self):
        self.logger.propagate = False
        s_hdlr = logging.StreamHandler()
        self.logger.addHandler(s_hdlr)

    
    def close(self):
        if self.test_thread is not None:
            hub.kill(self.test_thread)
        if self.ingress_event:
            self.ingress_event.set()
        hub.joinall([self.test_thread])
        

    def _register_sw(self, dp):
        status = True
        if isinstance(self.target_sw.dp, DummyDatapath) and dp.id == self.target_dpid:
            if dp.ofproto.OFP_VERSION != OfTester.target_ver:
                msg = 'Join target SW, but ofp version is not %s.' % \
                    self._get_version_desc(OfTester.target_ver)
            else:
                self.target_sw.dp = dp
                msg = 'Join target SW.'
        elif dp.id == self.tester_dpid:
            if dp.ofproto.OFP_VERSION != OfTester.tester_ver:
                msg = 'Join tester SW, but ofp version is not %s.' % \
                    self._get_version_desc(OfTester.tester_ver)
            else:
                self.tester_sw.dp = dp
                msg = 'Join tester SW.'
        else:
            msg = 'Connect unknown SW.'
            status = False
        if dp.id:
            self.logger.info('dpid=%s : %s',
                             dpid_lib.dpid_to_str(dp.id), msg)

        if not (isinstance(self.target_sw.dp, DummyDatapath) or
                isinstance(self.tester_sw.dp, DummyDatapath)):
            if self.sw_waiter is not None:
                self.sw_waiter.set()

        return status

    def _unregister_sw(self):
        self.target_sw.dp = DummyDatapath()
        self.tester_sw.dp = DummyDatapath()
              

    def synchronized(func):
        func.__lock__ = threading.Lock()
        def synced_func(*args, **kws):
            with func.__lock__:
                return func(*args, **kws)
        return synced_func  

    def _wait(self):
        """ Wait until specific OFP message received
             or timer is exceeded. """
        assert self.waiter is None

        self.waiter = hub.Event()
        self.rcv_msgs = []
        timeout = False

        timer = hub.Timeout(WAIT_TIMER)
        try:
            self.waiter.wait()
        except hub.Timeout as t:
            if t is not timer:
                raise RyuException('Internal error. Not my timeout.')
            timeout = True
        finally:
            timer.cancel()

        self.waiter = None

        if timeout:
            raise TestTimeout(self.state)
        if (self.rcv_msgs and isinstance(
                self.rcv_msgs[0],
                self.rcv_msgs[0].datapath.ofproto_parser.OFPErrorMsg)):
            raise TestReceiveError(self.state, self.rcv_msgs[0], OfTester.target_ver)


    @set_ev_cls([ofp_event.EventOFPFlowStatsReply,
                 ofp_event.EventOFPMeterConfigStatsReply,
                 ofp_event.EventOFPTableStatsReply,
                 ofp_event.EventOFPPortStatsReply,
                 ofp_event.EventOFPGroupDescStatsReply,
                 ofp_event.EventOFPPortDescStatsReply],
                handler.MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        # keys: stats reply event classes
        # values: states in which the events should be processed
        event_states = {
            ofp_event.EventOFPFlowStatsReply:
                [STATE_FLOW_EXIST_CHK,
                 STATE_THROUGHPUT_FLOW_EXIST_CHK,
                 STATE_GET_THROUGHPUT,
                 STATE_TARGET_FLOWS,
                 STATE_TESTER_FLOWS],
            ofp_event.EventOFPMeterConfigStatsReply:
                [STATE_METER_EXIST_CHK],
            ofp_event.EventOFPTableStatsReply:
                [STATE_GET_MATCH_COUNT,
                 STATE_FLOW_UNMATCH_CHK],
            ofp_event.EventOFPPortStatsReply:
                [STATE_TARGET_PKT_COUNT,
                 STATE_TESTER_PKT_COUNT],
            ofp_event.EventOFPGroupDescStatsReply:
                [STATE_GROUP_EXIST_CHK],
            ofp_event.EventOFPPortDescStatsReply:
                [STATE_GET_PORT_DESC]
        }
        if self.state in event_states[ev.__class__]:
            if self.waiter and ev.msg.xid in self.send_msg_xids:
                self.rcv_msgs.append(ev.msg)
                if not ev.msg.flags & \
                        ev.msg.datapath.ofproto.OFPMPF_REPLY_MORE:
                    self.waiter.set()
                    hub.sleep(0)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, handler.MAIN_DISPATCHER)
    def barrier_reply_handler(self, ev):
        state_list = [STATE_INIT_FLOW,
                      STATE_INIT_THROUGHPUT_FLOW,
                      STATE_INIT_METER,
                      STATE_INIT_GROUP,
                      STATE_FLOW_INSTALL,
                      STATE_THROUGHPUT_FLOW_INSTALL,
                      STATE_METER_INSTALL,
                      STATE_GROUP_INSTALL,
                      STATE_SEND_BARRIER]
        if self.state in state_list:
            if self.waiter and ev.msg.xid in self.send_msg_xids:
                self.rcv_msgs.append(ev.msg)
                self.waiter.set()
                hub.sleep(0)

    @set_ev_cls(ofp_event.EventOFPPacketIn, handler.MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        datapath = ev.msg.datapath
        if datapath.id != self.target_dpid and datapath.id != self.tester_dpid:
            return
        state_list = [STATE_FLOW_MATCH_CHK]

        if self.state in state_list:
            if self.waiter:
                self.rcv_msgs.append(ev.msg)
                self.waiter.set()
                hub.sleep(0)
        
    @set_ev_cls(ofp_event.EventOFPErrorMsg, [handler.HANDSHAKE_DISPATCHER,
                                             handler.CONFIG_DISPATCHER,
                                             handler.MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        if ev.msg.xid in self.send_msg_xids:
            self.rcv_msgs.append(ev.msg)
            if self.waiter:
                self.waiter.set()
                hub.sleep(0)


    @set_ev_cls(ofp_event.EventOFPStateChange,
                [handler.MAIN_DISPATCHER, handler.DEAD_DISPATCHER])
    def dispacher_change(self, ev):
        assert ev.datapath is not None
        if ev.state == handler.MAIN_DISPATCHER:
            self.evnet_ofp_state_change = ev.state
            if ev.datapath.id is not None:
                self.connected_list[ev.datapath.id] = ev.datapath

        elif ev.state == handler.DEAD_DISPATCHER:
            self.evnet_ofp_state_change = ev.state
            if ev.datapath.id is not None:
                del self.connected_list[ev.datapath.id] 

    # Rest Request 
    @set_ev_cls([rest_event.EventTestItemRequest,
                 rest_event.EventTestItemResultRequest,
                 rest_event.EventTestItemStopRequest,
                 rest_event.EventCheckLinkRequest,
                 rest_event.EventCheckLinkResultRequest,
                 rest_event.EventCheckLinkStopRequest])
    def test_request_handler(self,  req):
        self._start_handle_thread(req)


    @synchronized
    def _start_handle_thread(self, req):
        def _get_result():
            return {
                RESULT_TARGET_DPID : self.target_dpid,
                RESULT_EXECUTE_STATE : self.test_thread_state,
                RESULT_EXECUTE_DESC : THREAD_STATE_STR[self.test_thread_state]
            }

        if isinstance(req, rest_event.EventTestItemRequest):
            thread_desc = self._do_item_test(req)
            rep = rest_event.EventTestItemReply(req.src, _get_result())
        elif isinstance(req, rest_event.EventTestItemResultRequest):
            thread_desc = self._get_item_test(req)
            result = _get_result()
            result[RESULT_REPORT] = self.test_report
            rep = rest_event.EventTestItemResultReply(req.src, result)
        elif isinstance(req, rest_event.EventTestItemStopRequest):
            thread_desc = self._stop_item_test()
            rep = rest_event.EventCheckLinkResultReply(req.src, _get_result())

        elif isinstance(req, rest_event.EventCheckLinkRequest):
            thread_desc = self._do_check_link(req)
            rep = rest_event.EventTestItemStopReply(req.src, _get_result())
        elif isinstance(req, rest_event.EventCheckLinkResultRequest):
            thread_desc = self._get_check_link(req)
            result = _get_result()
            result[RESULT_REPORT] = self.test_report
            rep = rest_event.EventCheckLinkReply(req.src, result)
        elif isinstance(req, rest_event.EventCheckLinkStopRequest):
            thread_desc = self._stop_check_link(req)
            rep = rest_event.EventCheckLinkStopReply(req.src, _get_result())
    
        self.reply_to_request(req, rep)

    def _execute_thread(self, func, req):
        try :
            if  self.test_thread_state != THREAD_STATE_RUNNING and \
                self.test_thread_state != THREAD_STATE_START_SUCEESS:

                self.__init(req)
                self.test_thread = hub.spawn(func,req)

                if self.test_thread == None:
                    self.test_thread_state = THREAD_STATE_START_FAILURE
                else :
                    self.test_thread_state = THREAD_STATE_START_SUCEESS
            else :
                self.test_thread_state = THREAD_STATE_RUNNING
        except RegisterException as err :
            self.test_thread_state = THREAD_STATE_REGISTER_DPID_ERROR
            return "%s(dpid=%s)" % (THREAD_STATE_STR[self.test_thread_state], err.dpid)
        except (ValueError, TypeError) as err:
            self.test_thread_state = THREAD_STATE_TEST_PATTERN_ERROR
            return "%s(%s)" % (THREAD_STATE_STR[self.test_thread_state], err.message)
        return THREAD_STATE_STR[self.test_thread_state]

    def _get_thread(self):
        if  self.test_thread_state == THREAD_STATE_START_SUCEESS:
            self.test_thread_state = THREAD_STATE_RUNNING

    def _stop_thread(self):
        if self.test_thread_state == THREAD_STATE_RUNNING or \
            self.test_thread_state == THREAD_STATE_START_SUCEESS :
            self.close()
        self._test_end('--- Test terminated ---')

    def _do_item_test(self, req):
        return self._execute_thread(self._test_items_execute, req)

    def _get_item_test(self, req):
        self._get_thread()

    def _stop_item_test(self):
        self._stop_thread()

    def _do_check_link(self, req):
        return self._execute_thread(self._test_check_links_execute, req)

    def _get_check_link(self, req):
        self._get_thread()

    def _stop_check_link(self, req):
        self._stop_thread()
        

    def _test_check_links_execute(self, req):
        report = self._test_check_link_execute()
        self.logger.info(report)
        self.test_report.append(report)
        self._test_end(msg='---  Test end  ---', report=None) 

    def _test_check_link_execute(self):
        if isinstance(self.target_sw.dp, DummyDatapath) or \
                isinstance(self.tester_sw.dp, DummyDatapath):
            self.logger.info('waiting for switches connection...')
            self.sw_waiter = hub.Event()
            self.sw_waiter.wait()
            self.sw_waiter = None

        self.logger.info('--- Execute Check Links ---')
        report = {}
        report[RESULT_REPORT_STATUS] = RESULT_OK
        i = -1
        try:
            # check target port
            report[RESULT_REPORT_PORT_LINK_STATE] = self._get_port_link_status()
                    
            check_send_port = [
                {"STATUS": "NO TEST", "INFO":"target_recv_port<->tester_send_port"},
                {"STATUS": "NO TEST", "INFO":"tester_recv_port_1<->target_send_port_1"},
                {"STATUS": "NO TEST", "INFO":"tester_recv_port_2<->target_send_port_2"}]

            i=i+1
            self._check_send_port(TARGET_RECV_PORT,
                                    TESTER_SEND_PORT)
            check_send_port[i]["STATUS"] = "OK"

            i=i+1
            self._check_send_port(TESTER_RECV_PORT_1,
                                        TARGET_SEND_PORT_1)
            check_send_port[i]["STATUS"] = "OK"
            
            i=i+1
            self._check_send_port(TESTER_RECV_PORT_2, 
                                        TARGET_SEND_PORT_2)
            check_send_port[i]["STATUS"] = "OK"
        except (TestReceiveError, TestFailure,
                TestTimeout, TestError) as err:
            print type(err)
            report[RESULT_REPORT_STATUS] = RESULT_ERROR
            report[RESULT_REPORT_TEST_STATE] = STATE_STR[self.state]
            report[RESULT_REPORT_TEST_REASON] =  str(err)
            if i >= 0: check_send_port[i]["STATUS"] = "FAILURE"
        except Exception as err :
            print type(err)
            report[RESULT_REPORT_STATUS] = RESULT_ERROR
            report[RESULT_REPORT_TEST_STATE] = STATE_STR[self.state]
            report[RESULT_REPORT_TEST_REASON] =  str(err)
            if i >= 0: check_send_port[i]["STATUS"] = "FAILURE"
        finally:
            self.ingress_event = None
            for tid in self.ingress_threads:
                hub.kill(tid)
            self.ingress_threads = []
        
        report[RESULT_REPORT_CHECK_SEND_PORT] = check_send_port

        hub.sleep(0)
        return report

    def _test_items_execute(self, req):
        report = {}
        test_pattens = TestPatterns(self.map_port, req, 
                                    self.logger, req.parse_tests)
        self.description = test_pattens.description
        for i, test_item in enumerate(test_pattens.test_items):
            desc = test_pattens.description if i == 0 else None
            report = self._test_item_execute(test_item, desc)
            self.logger.info(report)
            self.test_report.append(report)
        self._test_end(msg='---  Test end  ---', report=None) 

    def _test_item_execute(self, test_item, description):
        if isinstance(self.target_sw.dp, DummyDatapath) or \
                isinstance(self.tester_sw.dp, DummyDatapath):
            self.logger.info('waiting for switches connection...')
            self.sw_waiter = hub.Event()
            self.sw_waiter.wait()
            self.sw_waiter = None

        self.logger.info('--- Execute Test Item ---')
        if description:
            self.logger.info('%s', description)
        self.thread_msg = None
        
        # Test execute.
        report = {}
        report[RESULT_REPORT_STATUS] = RESULT_OK
        report[RESULT_REPORT_TEST_ITEM] = test_item.description
        target_pkt_count = []
        tester_pkt_count = []
        try:
            # Initialize.
            self._test(STATE_INIT_METER, self.target_sw)
            self._test(STATE_INIT_GROUP, self.target_sw)
            self._test(STATE_INIT_FLOW, self.target_sw)

            self._test(STATE_INIT_METER, self.tester_sw)
            self._test(STATE_INIT_GROUP, self.tester_sw)
            self._test(STATE_INIT_FLOW, self.tester_sw)
            self._test(STATE_INIT_THROUGHPUT_FLOW, self.tester_sw,
                                    THROUGHPUT_COOKIE)
            
            # Install flows to tester
            flow = self.tester_sw.get_flow(
                in_port=self.tester_recv_port_1,
                out_port=self.tester_sw.dp.ofproto.OFPP_CONTROLLER,
                priority=TESTER_PRIORITY)
            expected_flow = [flow, SW_TESTER]
            self._test(STATE_FLOW_INSTALL, self.tester_sw, flow )
            self._test(STATE_FLOW_EXIST_CHK,
                        self.tester_sw.send_flow_stats, flow)

            flow = self.target_sw.get_flow(
                in_port=None,
                out_port=None,
                priority=0)
            expected_flow = [flow, SW_TARGET]
            self._test(STATE_FLOW_INSTALL, self.target_sw, flow )
            self._test(STATE_FLOW_EXIST_CHK,
                        self.target_sw.send_flow_stats, flow)
            
            # Install flows to target
            for flow in test_item.prerequisite:
                if isinstance(
                        flow, self.target_sw.dp.ofproto_parser.OFPFlowMod):
                    expected_flow = [flow, SW_TARGET]
                    self._test(STATE_FLOW_INSTALL, self.target_sw, flow)
                    self._test(STATE_FLOW_EXIST_CHK,
                        self.target_sw.send_flow_stats, flow)
                    
                elif isinstance(
                        flow, self.target_sw.dp.ofproto_parser.OFPMeterMod):
                    expected_flow = [flow, SW_TARGET]
                    self._test(STATE_METER_INSTALL, self.target_sw, flow)
                    self._test(STATE_METER_EXIST_CHK,
                            self.target_sw.send_meter_config_stats, flow)

                elif isinstance(
                        flow, self.target_sw.dp.ofproto_parser.OFPGroupMod):
                    expected_flow = [flow, SW_TARGET]
                    self._test(STATE_GROUP_INSTALL, self.target_sw, flow)
                    self._test(STATE_GROUP_EXIST_CHK,
                            self.target_sw.send_group_desc_stats, flow)

            if len(test_item.tests) > 0:
                # Do tests.

                for pkt in test_item.tests:
                    # Get stats before sending packet(s).
                    if KEY_EGRESS in pkt or KEY_PKT_IN in pkt:
                        target_pkt_count.append(self._test(STATE_TARGET_PKT_COUNT,
                                                       True))
                        tester_pkt_count.append(self._test(STATE_TESTER_PKT_COUNT,
                                                       False))
                    elif KEY_THROUGHPUT in pkt:
                        # install flows for throughput analysis
                        for throughput in pkt[KEY_THROUGHPUT]:
                            flow = throughput[KEY_FLOW]
                            self._test(STATE_THROUGHPUT_FLOW_INSTALL,
                                   self.tester_sw, flow)
                            self._test(STATE_THROUGHPUT_FLOW_EXIST_CHK,
                                   self.tester_sw.send_flow_stats, flow)

                        start = self._test(STATE_GET_THROUGHPUT)
                    elif KEY_TBL_MISS in pkt:
                        before_stats = self._test(STATE_GET_MATCH_COUNT)

                    # Send packet(s).
                    if KEY_INGRESS in pkt:
                        self._one_time_packet_send(pkt)
                    elif KEY_PACKETS in pkt:
                        self._continuous_packet_send(pkt)

                    # Check a result.
                    if KEY_EGRESS in pkt or KEY_PKT_IN in pkt:      
                        result = self._test(STATE_FLOW_MATCH_CHK, pkt)
                        if result == TIMEOUT:
                            target_pkt_count.append(self._test(
                                STATE_TARGET_PKT_COUNT, True))
                            tester_pkt_count.append(self._test(
                                STATE_TESTER_PKT_COUNT, False))
                            test_type = (KEY_EGRESS if KEY_EGRESS in pkt
                                         else KEY_PKT_IN)
                            self._test(STATE_NO_PKTIN_REASON, test_type,
                                       target_pkt_count, tester_pkt_count)

                        # Get Flow Entry from target
                        target_flow = self._test(STATE_TARGET_FLOWS,
                                        self.target_sw, self.target_ofctl)
                        self._test(STATE_TARGET_FLOW_COUNT_CHK, 
                                        self.target_sw, target_flow) 
                    elif KEY_THROUGHPUT in pkt:
                        end = self._test(STATE_GET_THROUGHPUT)
                        self._test(STATE_THROUGHPUT_CHK, pkt[KEY_THROUGHPUT],
                                   start, end)
                    elif KEY_TBL_MISS in pkt:
                        self._test(STATE_SEND_BARRIER)
                        hub.sleep(INTERVAL)
                        self._test(STATE_FLOW_UNMATCH_CHK, before_stats, pkt)

        except (TestReceiveError, TestFailure,
                TestTimeout, TestError) as err:
            print type(err)
            err_state = self.state
            report[RESULT_REPORT_STATUS] = RESULT_ERROR
            report[RESULT_REPORT_TEST_STATE] = STATE_STR[self.state]
            report[RESULT_REPORT_TEST_REASON] =  str(err)
        except Exception as err :
            print type(err)
            err_state = self.state
            report[RESULT_REPORT_STATUS] = RESULT_ERROR
            report[RESULT_REPORT_TEST_STATE] = STATE_STR[self.state]
            report[RESULT_REPORT_TEST_REASON] =  str(err)
        finally:
            self.ingress_event = None
            for tid in self.ingress_threads:
                hub.kill(tid)
            self.ingress_threads = []

        if report[RESULT_REPORT_STATUS] != RESULT_OK:
            report[RESULT_REPORT_SW_INFO] = {}
            target_info = {RESULT_REPORT_EXPECTED_FLOW:[]}
            tester_info = {RESULT_REPORT_EXPECTED_FLOW:[]}

            expected_flow = [flow, SW_TARGET]
            if expected_flow[1] == SW_TARGET and isinstance(
                expected_flow[0], self.target_sw.dp.ofproto_parser.OFPFlowMod):
                target_info[RESULT_REPORT_EXPECTED_FLOW].append(
                    self._flow_mod_to_rest(expected_flow[0], 
                                            self.target_ofctl))
            elif expected_flow[1] == SW_TARGET and isinstance(
                expected_flow[0], self.target_sw.dp.ofproto_parser.OFPMeterMod):
                target_info[RESULT_REPORT_EXPECTED_FLOW].append(
                    self._meter_mod_to_rest(self.target_sw.dp.ofproto_parser,
                                            expected_flow[0], 
                                            self.target_ofctl))
            elif expected_flow[1] == SW_TARGET and isinstance(
                expected_flow[0], self.target_sw.dp.ofproto_parser.OFPGroupMod):
                target_info[RESULT_REPORT_EXPECTED_FLOW].append(
                        self._group_mod_to_rest(expected_flow[0], 
                                            self.target_ofctl))
            
            elif expected_flow[1] == SW_TESTER and isinstance(
                expected_flow[0], self.tester_sw.dp.ofproto_parser.OFPFlowMod):
                tester_info[RESULT_REPORT_EXPECTED_FLOW].append(
                        self._flow_mod_to_rest(expected_flow[0], 
                                            self.tester_ofctl))
            elif expected_flow[1] == SW_TESTER and isinstance(
                expected_flow[0], self.tester_sw.dp.ofproto_parser.OFPMeterMod):
                tester_info[RESULT_REPORT_EXPECTED_FLOW].append(
                        self._meter_mod_to_rest(self.tester_sw.dp.ofproto_parser,
                                            expected_flow[0], 
                                            self.tester_ofctl))
            elif expected_flow[1] == SW_TESTER and isinstance(
                expected_flow[0], self.tester_sw.dp.ofproto_parser.OFPGroupMod):
                tester_info[RESULT_REPORT_EXPECTED_FLOW].append(
                        self._group_mod_to_rest(expected_flow[0], 
                                            self.tester_ofctl))

            if self.target_dpid == self.tester_dpid:
                target_info[RESULT_REPORT_REAL_FLOW] = \
                    self._test(STATE_TARGET_FLOWS,self.target_sw, self.target_ofctl)

            else:
                target_info[RESULT_REPORT_REAL_FLOW] = \
                    self._test(STATE_TARGET_FLOWS,self.target_sw, self.target_ofctl)

                tester_info[RESULT_REPORT_REAL_FLOW] = \
                    self._test(STATE_TESTER_FLOWS,self.tester_sw, self.tester_ofctl)


            #if err_state in [  STATE_THROUGHPUT_FLOW_INSTALL, 
            #                    STATE_THROUGHPUT_FLOW_EXIST_CHK,
            #                    STATE_GET_THROUGHPUT, STATE_GET_MATCH_COUNT,
            #                    STATE_FLOW_MATCH_CHK, STATE_NO_PKTIN_REASON,
            #                STATE_SEND_BARRIER, STATE_FLOW_UNMATCH_CHK,
            #                    STATE_TARGET_FLOW_COUNT_CHK] :
  
            if len(target_pkt_count) > 0:
                target_info[RESULT_REPORT_BEFORE_PORT_STATE] = target_pkt_count[0][:]
                if len(target_pkt_count) < 2 :
                    target_pkt_count.append(
                            self._test(STATE_TARGET_PKT_COUNT, True))
                target_info[RESULT_REPORT_AFTER_PORT_STATE] = target_pkt_count[1][:]
            else :
                target_pkt_count.append(
                            self._test(STATE_TARGET_PKT_COUNT, True))
                target_info[RESULT_REPORT_BEFORE_PORT_STATE] = target_pkt_count[0][:]
                target_info[RESULT_REPORT_AFTER_PORT_STATE] = target_pkt_count[0][:]     
                
            if len(tester_pkt_count) > 0:
                tester_info[RESULT_REPORT_BEFORE_PORT_STATE] = tester_pkt_count[0][:]
                if len(tester_pkt_count) < 2:
                    tester_pkt_count.append(
                        self._test(STATE_TESTER_PKT_COUNT, False))
                tester_info[RESULT_REPORT_AFTER_PORT_STATE] = tester_pkt_count[1][:]
            else :
                tester_pkt_count.append(
                             self._test(STATE_TESTER_PKT_COUNT, False))
                tester_info[RESULT_REPORT_BEFORE_PORT_STATE] = tester_pkt_count[0][:]
                tester_info[RESULT_REPORT_AFTER_PORT_STATE] = tester_pkt_count[0][:]


            if self.target_dpid == self.tester_dpid:
                for state in tester_info[RESULT_REPORT_BEFORE_PORT_STATE]:
                    target_info[RESULT_REPORT_BEFORE_PORT_STATE].append(state)
        
                for state in tester_info[RESULT_REPORT_AFTER_PORT_STATE]:
                    target_info[RESULT_REPORT_AFTER_PORT_STATE].append(state)
                        
                report[RESULT_REPORT_SW_INFO][self.target_dpid] = target_info
            else:
                report[RESULT_REPORT_SW_INFO][self.target_dpid] = target_info
                report[RESULT_REPORT_SW_INFO][self.tester_dpid] = tester_info
            
            report[RESULT_REPORT_PORT_LINK_STATE] = self._get_port_link_status()
            report[RESULT_REPORT_SEND_PORT] = {
                        "name": TESTER_SEND_PORT,
                        "port": self.tester_send_port}
            report[RESULT_REPORT_OPERATING] = test_item.tests_str
        hub.sleep(0)
        return report

    def _get_port_link_status(self):
        # check target port
        ports_link_status = {
                TARGET_RECV_PORT  : {'state': "NOT EXISTS"},
                TARGET_SEND_PORT_1: {'state': "NOT EXISTS"},
                TARGET_SEND_PORT_2: {'state': "NOT EXISTS"},
                TESTER_SEND_PORT  : {'state': "NOT EXISTS"},
                TESTER_RECV_PORT_1: {'state': "NOT EXISTS"},
                TESTER_RECV_PORT_2: {'state': "NOT EXISTS"}
        }

        ports = self._test(STATE_GET_PORT_DESC, self.target_sw)
        if ports.has_key(self.target_recv_port):
            ports_link_status[TARGET_RECV_PORT] =\
                    ports[self.target_recv_port]

        if ports.has_key(self.target_send_port_1):
            ports_link_status[TARGET_SEND_PORT_1] =\
                    ports[self.target_send_port_1]
                
        if ports.has_key(self.target_send_port_2):
            ports_link_status[TARGET_SEND_PORT_2] =\
                    ports[self.target_send_port_2]
               
            
        # check tester port
        ports = self._test(STATE_GET_PORT_DESC, self.tester_sw)
        if ports.has_key(self.tester_send_port):    
            ports_link_status[TESTER_SEND_PORT] =\
                    ports[self.tester_send_port]
            
        if ports.has_key(self.tester_recv_port_1):
            ports_link_status[TESTER_RECV_PORT_1] =\
                    ports[self.tester_recv_port_1]
                
        if ports.has_key(self.tester_recv_port_2):
            ports_link_status[TESTER_RECV_PORT_2] =\
                    ports[self.tester_recv_port_2]

        return ports_link_status

    def _check_send_port(self, recv_port, send_port):

        pkt = { 
            KEY_INGRESS: '""""""\x12\x11\x11\x11\x11\x11\x08\x00E' \
                + ' \x00K\x00\x00\x00\x00@\x06\xdb\x1e\xc0\xa8'\
                + '\n\n\xc0\xa8\x14\x14+g\x08\xae\x00\x00\x00\x00'\
                + '\x00\x00\x00\x00`\x00\x00\x00\xcbL\x00\x00\x00'\
                + '\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n'\
                + '\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17'\
                + '\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f',
            KEY_EGRESS: '""""""\x12\x11\x11\x11\x11\x11\x08\x00E' \
                + ' \x00K\x00\x00\x00\x00@\x06\xdb\x1e\xc0\xa8'\
                + '\n\n\xc0\xa8\x14\x14+g\x08\xae\x00\x00\x00\x00'\
                + '\x00\x00\x00\x00`\x00\x00\x00\xcbL\x00\x00\x00'\
                + '\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n'\
                + '\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17'\
                + '\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'}

        # Initialize.
        self._test(STATE_INIT_METER, self.target_sw)
        self._test(STATE_INIT_GROUP, self.target_sw)
        self._test(STATE_INIT_FLOW, self.target_sw)
        
        self._test(STATE_INIT_METER, self.tester_sw)
        self._test(STATE_INIT_GROUP, self.tester_sw)
        self._test(STATE_INIT_FLOW, self.tester_sw)

        
        if recv_port.find("target_") < 0:
            send_sw = self.target_sw
            recv_sw = self.tester_sw
        else:
            send_sw = self.tester_sw
            recv_sw = self.target_sw
            

        #Install flow
        flow = recv_sw.get_flow(
            in_port=self.map_port[recv_port],
            out_port=recv_sw.dp.ofproto.OFPP_CONTROLLER)
        self._test(STATE_FLOW_INSTALL, recv_sw, flow )
        self._test(STATE_FLOW_EXIST_CHK,
                        recv_sw.send_flow_stats, flow)
 
        target_pkt_count = [self._test(STATE_TARGET_PKT_COUNT, True)]
        tester_pkt_count = [self._test(STATE_TESTER_PKT_COUNT, False)]
        
        # Send packet(s).
        self._packet_send(send_sw, self.map_port[send_port], pkt)
            
        result = self._test(STATE_FLOW_MATCH_CHK, pkt, False)
        if result == TIMEOUT:
            target_pkt_count.append(self._test(
                                STATE_TARGET_PKT_COUNT, True))
            tester_pkt_count.append(self._test(
                                STATE_TESTER_PKT_COUNT, False))
            test_type = (KEY_EGRESS if KEY_EGRESS in pkt
                                         else KEY_PKT_IN)
            self._test(STATE_NO_PKTIN_REASON, test_type,
                                       target_pkt_count, tester_pkt_count, send_port)

    def _test_end(self, msg=None, report=None):
        self.test_thread = None
        self.test_thread_state = THREAD_STATE_READY
        if msg:
            self.logger.info(msg)
        #if report:
        #    self._output_test_report(report)
        #pid = os.getpid()
        #os.kill(pid, signal.SIGTERM)

    def _test(self, state, *args):
        test = {STATE_INIT_FLOW: self._test_initialize_flow,
                STATE_INIT_THROUGHPUT_FLOW: self._test_initialize_flow,
                STATE_INIT_METER: self._test_initialize_meter,
                STATE_INIT_GROUP: self._test_initialize_groups,
                STATE_FLOW_INSTALL: self._test_msg_install,
                STATE_THROUGHPUT_FLOW_INSTALL: self._test_msg_install,
                STATE_METER_INSTALL: self._test_msg_install,
                STATE_GROUP_INSTALL: self._test_msg_install,
                STATE_FLOW_EXIST_CHK: self._test_exist_check,
                STATE_THROUGHPUT_FLOW_EXIST_CHK: self._test_exist_check,
                STATE_METER_EXIST_CHK: self._test_exist_check,
                STATE_GROUP_EXIST_CHK: self._test_exist_check,
                STATE_TARGET_PKT_COUNT: self._test_get_packet_count,
                STATE_TESTER_PKT_COUNT: self._test_get_packet_count,
                STATE_FLOW_MATCH_CHK: self._test_flow_matching_check,
                STATE_NO_PKTIN_REASON: self._test_no_pktin_reason_check,
                STATE_GET_MATCH_COUNT: self._test_get_match_count,
                STATE_SEND_BARRIER: self._test_send_barrier,
                STATE_FLOW_UNMATCH_CHK: self._test_flow_unmatching_check,
                STATE_GET_THROUGHPUT: self._test_get_throughput,
                STATE_THROUGHPUT_CHK: self._test_throughput_check,
                STATE_TARGET_FLOWS: self._get_flows_state,
                STATE_TESTER_FLOWS: self._get_flows_state,
                STATE_GET_PORT_DESC: self._get_port_desc_state,
                STATE_TARGET_FLOW_COUNT_CHK: self._test_flow_count
                }

        self.send_msg_xids = []
        self.rcv_msgs = []

        self.state = state
        return test[state](*args)

    def send_barrier_request(self):
        """ send a BARRIER_REQUEST message."""
        parser = self.dp.ofproto_parser
        req = parser.OFPBarrierRequest(self.dp)
        return self.send_msg(req)

    def _test_initialize_flow(self, datapath, cookie=0):
        xid = datapath.del_flows(cookie)
        self.send_msg_xids.append(xid)
        xid = datapath.send_barrier_request()
        self.send_msg_xids.append(xid)
        self._wait()

        assert len(self.rcv_msgs) == 1
        msg = self.rcv_msgs[0]
        assert isinstance(msg, datapath.dp.ofproto_parser.OFPBarrierReply)


    def _test_initialize_meter(self, datapath):
        return datapath.del_meters()

    def _test_initialize_groups(self, datapath):
        return datapath.del_groups()

    def _test_msg_install(self, datapath, message):
        xid = datapath.send_msg(message)
        self.send_msg_xids.append(xid)

        xid = datapath.send_barrier_request()
        self.send_msg_xids.append(xid)

        self._wait()
        assert len(self.rcv_msgs) == 1
        msg = self.rcv_msgs[0]
        assert isinstance(msg, datapath.dp.ofproto_parser.OFPBarrierReply)

    def _flow_mod_to_rest(self, msg, ofctl):
        stats = msg
        actions = ofctl.actions_to_str(stats.instructions)
        match = ofctl.match_to_str(stats.match)

        flow = {'priority'      : stats.priority,
                'cookie'        : stats.cookie,
                'idle_timeout'  : stats.idle_timeout,
                'hard_timeout'  : stats.hard_timeout,
                'actions'       : actions,
                'match'         : match,
                'table_id'      : stats.table_id,
                'flags'         : stats.flags}
        return flow

    def _meter_mod_to_rest(self, ofproto_parser, msg, ofctl):
        stats = msg
        bds = []
        for band in stats.bands:
            if isinstance(band, ofproto_parser.OFPMeterBandDrop):
                b = {'burst_size': band.burst_size,
                    'rate'       : band.rate,
                    'type'       : band.type }
            elif isinstance(band,ofproto_parser.OFPMeterBandDscpRemark):
                b = {'burst_size': band.burst_size,
                    'rate'       : band.rate,
                    'prec_level' : band.prec_level}
            bds.append(b) 

        flow = {'bands'     : bds,
                'flags'     : stats.flags,
                'meter_id'  : stats.meter_id}
        return flow

    def _group_mod_to_rest(self, msg, ofctl):
        stats = msg
        bkt = []
        for bucket in stats.buckets:
            if isinstance(band, ofproto_parser.OFPBucket):
                b = {'weight'       : bucket.weight,
                    'watch_port'    : bucket.watch_port,
                    'watch_group'   : bucket.watch_group,
                    'actions'       : bucket.actions}
                bkt.append(b) 

        flow = {'buckets'   : bkt,
                'group_id'  : stats.group_id,
                'type'      : stats.type}
        return flow

    def _state_flow_to_rest(self, msgs,ofctl):
        flows = []
        for msg in msgs:
            for stats in msg.body:
                actions = ofctl.actions_to_str(stats.instructions)
                match = ofctl.match_to_str(stats.match)

                s = {'priority'     : stats.priority,
                    'cookie'        : stats.cookie,
                    'idle_timeout'  : stats.idle_timeout,
                    'hard_timeout'  : stats.hard_timeout,
                    'actions'       : actions,
                    'match'         : match,
                    'byte_count'    : stats.byte_count,
                    'duration_sec'  : stats.duration_sec,
                    'duration_nsec' : stats.duration_nsec,
                    'packet_count'  : stats.packet_count,
                    'table_id'      : stats.table_id,
                    'length'        : stats.length,
                    'flags'         : stats.flags}
                flows.append(s)
        return flows

    def _get_flows_state(self, sw, ofctl):
        method = sw.send_flow_stats
        parser = method.__self__.dp.ofproto_parser
        xid = method()
        self.send_msg_xids.append(xid)
        self._wait()

        return self._state_flow_to_rest(self.rcv_msgs,ofctl)
        #return self.rcv_msgs[0].body
    
    def _get_port_desc_state(self, sw):
        method = sw.send_port_desc_stats
        xid = method()
        self.send_msg_xids.append(xid)
        self._wait()

        descs = {}
        msgs = self.rcv_msgs
        for msg in msgs: 
            stats = msg.body
            for stat in stats:
                if stat.state == 1: desc = {'state': "DOWN"}
                else: desc = {'state': "UP"}
                descs[stat.port_no] = desc
        return descs

    def _test_exist_check(self, method, message):
        parser = method.__self__.dp.ofproto_parser
        method_dict = {
            OpenFlowSw.send_flow_stats.__name__: {
                'reply': parser.OFPFlowStatsReply,
                'compare': self._compare_flow
            },
            OpenFlowSw.send_meter_config_stats.__name__: {
                'reply': parser.OFPMeterConfigStatsReply,
                'compare': self._compare_meter
            },
            OpenFlowSw.send_group_desc_stats.__name__: {
                'reply': parser.OFPGroupDescStatsReply,
                'compare': self._compare_group
            }
        }
        xid = method()
        self.send_msg_xids.append(xid)
        self._wait()

        ng_stats = []
        for msg in self.rcv_msgs:
            assert isinstance(msg, method_dict[method.__name__]['reply'])
           
            for stats in msg.body:
                result, stats = method_dict[method.__name__]['compare'](
                    stats, message)
                if result:
                    return
                else:
                    ng_stats.append(stats)
        error_dict = {
            OpenFlowSw.send_flow_stats.__name__:
                {'flows': ', '.join(ng_stats)},
            OpenFlowSw.send_meter_config_stats.__name__:
                {'meters': ', '.join(ng_stats)},
            OpenFlowSw.send_group_desc_stats.__name__:
                {'groups': ', '.join(ng_stats)}
        }
        raise TestFailure(self.state, **error_dict[method.__name__])


    def _compare_flow(self, stats1, stats2):
        def __reasm_match(match):
            """ reassemble match_fields. """
            mask_lengths = {'vlan_vid': 12 + 1,
                            'ipv6_flabel': 20,
                            'ipv6_exthdr': 9}
            match_fields = list()
            for key, united_value in match.iteritems():
                if isinstance(united_value, tuple):
                    (value, mask) = united_value
                    # look up oxm_fields.TypeDescr to get mask length.
                    for ofb in stats2.datapath.ofproto.oxm_types:
                        if ofb.name == key:
                            # create all one bits mask
                            mask_len = mask_lengths.get(
                                key, ofb.type.size * 8)
                            all_one_bits = 2 ** mask_len - 1
                            # convert mask to integer
                            mask_bytes = ofb.type.from_user(mask)
                            oxm_mask = int(binascii.hexlify(mask_bytes), 16)
                            # when mask is all one bits, remove mask
                            if oxm_mask & all_one_bits == all_one_bits:
                                united_value = value
                            # when mask is all zero bits, remove field.
                            elif oxm_mask & all_one_bits == 0:
                                united_value = None
                            break
                if united_value is not None:
                    match_fields.append((key, united_value))
            return match_fields

        attr_list = ['cookie', 'priority', 'hard_timeout', 'idle_timeout',
                     'table_id', 'instructions', 'match']
        for attr in attr_list:
            value1 = getattr(stats1, attr)
            value2 = getattr(stats2, attr)
            if attr == 'instructions':
                value1 = sorted(value1)
                value2 = sorted(value2)
                if len(value1) == 0:
                    if len(value2) == 0 or \
                        len(value2[0].actions) == 0:
                        value2 = []
            elif attr == 'match':
                value1 = sorted(__reasm_match(value1))
                value2 = sorted(__reasm_match(value2))
            if str(value1) != str(value2):
                flow_stats = []
                for attr in attr_list:
                    flow_stats.append('%s=%s' % (attr, getattr(stats1, attr)))
                return False, 'flow_stats(%s)' % ','.join(flow_stats)
        return True, None
    
    def _compare_meter(self, stats1, stats2):
        """compare the message used to install and the message got from
           the switch."""
        attr_list = ['flags', 'meter_id', 'bands']
        for attr in attr_list:
            value1 = getattr(stats1, attr)
            value2 = getattr(stats2, attr)
            if str(value1) != str(value2):
                meter_stats = []
                for attr in attr_list:
                    meter_stats.append('%s=%s' % (attr, getattr(stats1, attr)))
                return False, 'meter_stats(%s)' % ','.join(meter_stats)
        return True, None

    def _compare_group(self, stats1, stats2):
        attr_list = ['type', 'group_id', 'buckets']
        for attr in attr_list:
            value1 = getattr(stats1, attr)
            value2 = getattr(stats2, attr)
            if str(value1) != str(value2):
                group_stats = []
                for attr in attr_list:
                    group_stats.append('%s=%s' % (attr, getattr(stats1, attr)))
                return False, 'group_stats(%s)' % ','.join(group_stats)
            return True, None

    def _diff_packets(self, model_pkt, rcv_pkt):
        msg = []
        for rcv_p in rcv_pkt.protocols:
            if type(rcv_p) != str:
                model_protocols = model_pkt.get_protocols(type(rcv_p))
                if len(model_protocols) == 1:
                    model_p = model_protocols[0]
                    diff = []
                    for attr in rcv_p.__dict__:
                        if attr.startswith('_'):
                            continue
                        if callable(attr):
                            continue
                        if hasattr(rcv_p.__class__, attr):
                            continue
                        rcv_attr = repr(getattr(rcv_p, attr))
                        model_attr = repr(getattr(model_p, attr))
                        if rcv_attr != model_attr:
                            diff.append('%s=%s' % (attr, rcv_attr))
                    if diff:
                        msg.append('%s(%s)' %
                                   (rcv_p.__class__.__name__,
                                    ','.join(diff)))
                else:
                    if (not model_protocols or
                            not str(rcv_p) in str(model_protocols)):
                        msg.append(str(rcv_p))
            else:
                model_p = ''
                for p in model_pkt.protocols:
                    if type(p) == str:
                        model_p = p
                        break
                if model_p != rcv_p:
                    msg.append('str(%s)' % repr(rcv_p))
        if msg:
            return '/'.join(msg)
        else:
            return ('Encounter an error during packet comparison.'
                    ' it is malformed.')

    def _test_flow_matching_check(self, pkt, check_packtin_id=True):
        self.logger.debug("egress:[%s]", packet.Packet(pkt.get(KEY_EGRESS)))
        self.logger.debug("packet_in:[%s]",
                          packet.Packet(pkt.get(KEY_PKT_IN)))

        # receive a PacketIn message.
        try:
            self._wait()
        except TestTimeout:
            return TIMEOUT

        assert len(self.rcv_msgs) == 1
        msg = self.rcv_msgs[0]
        # Compare a received message with OFPPacketIn
        #
        # We compare names of classes instead of classes themselves
        # due to OVS bug. The code below should be as follows:
        #
        # assert isinstance(msg, msg.datapath.ofproto_parser.OFPPacketIn)
        #
        # At this moment, OVS sends Packet-In messages of of13 even if
        # OVS is configured to use of14, so the above code causes an
        # assertion.
        assert msg.__class__.__name__ == 'OFPPacketIn'
        self.logger.debug("dpid=%s : receive_packet[%s]",
                          dpid_lib.dpid_to_str(msg.datapath.id),
                          packet.Packet(msg.data))

        # check the SW which sended PacketIn and output packet.
        pkt_in_src_model = (self.tester_sw if KEY_EGRESS in pkt
                            else self.target_sw)
        model_pkt = (pkt[KEY_EGRESS] if KEY_EGRESS in pkt
                     else pkt[KEY_PKT_IN])

        #if hasattr(msg.datapath.ofproto, "OFPR_NO_MATCH"):
        #    table_miss_value = msg.datapath.ofproto.OFPR_NO_MATCH
        #else:
        #    table_miss_value = msg.datapath.ofproto.OFPR_TABLE_MISS
        if check_packtin_id == True and \
                msg.datapath.id != pkt_in_src_model.dp.id:
            pkt_type = 'packet-in'
            err_msg = 'SW[dpid=%s]' % dpid_lib.dpid_to_str(msg.datapath.id)
        #elif msg.reason == table_miss_value or \
        elif msg.reason == msg.datapath.ofproto.OFPR_INVALID_TTL:
            pkt_type = 'packet-in'
            err_msg = 'OFPPacketIn[reason=%d]' % msg.reason
        elif repr(msg.data) != repr(model_pkt):
            pkt_type = 'packet'
            err_msg = self._diff_packets(packet.Packet(model_pkt),
                                         packet.Packet(msg.data))
        else:
            return RESULT_OK

        raise TestFailure(self.state, pkt_type=pkt_type,
                          detail=err_msg)

    def _test_get_packet_count(self, is_target):
        sw = self.target_sw if is_target else self.tester_sw
        xid = sw.send_port_stats()
        self.send_msg_xids.append(xid)
        self._wait()
        result = []

        if sw == self.target_sw:
            for port in [TARGET_RECV_PORT, TARGET_SEND_PORT_1, 
                            TARGET_SEND_PORT_2]:
                result.append({ 'port_no': self.map_port[port],
                                'name'   : port,
                                'rx_packets': -1,
                                'tx_packets': -1,
                                'rx_bytes'  : -1,
                                'tx_bytes'  : -1})
        else :
            for port in [TESTER_SEND_PORT, TESTER_RECV_PORT_1, 
                            TESTER_RECV_PORT_2]:
                result.append({ 'port_no': self.map_port[port],
                                'name'   : port,
                                'rx_packets': -1,
                                'tx_packets': -1,
                                'rx_bytes'  : -1,
                                'tx_bytes'  : -1})

        for msg in self.rcv_msgs:
            for stats in msg.body:
                match = False
                if sw == self.target_sw:
                    if stats.port_no == self.map_port[TARGET_RECV_PORT] or\
                        stats.port_no == self.map_port[TARGET_SEND_PORT_1] or\
                        stats.port_no == self.map_port[TARGET_SEND_PORT_2]:
                        match = True
                elif sw == self.tester_sw:
                    if stats.port_no == self.map_port[TESTER_SEND_PORT] or\
                        stats.port_no == self.map_port[TESTER_RECV_PORT_1] or\
                        stats.port_no == self.map_port[TESTER_RECV_PORT_2]:
                        match = True

                if match :
                    for r in result:
                        if r['port_no'] == stats.port_no:
                            r['rx_packets'] = stats.rx_packets
                            r['tx_packets'] = stats.tx_packets
                            r['rx_bytes']   = stats.rx_bytes
                            r['tx_bytes']   = stats.tx_bytes
        return result



    def _test_no_pktin_reason_check(self, test_type,
                                    target_pkt_count, tester_pkt_count,
                                    send_port=None):

        def _get_value(pkt_count, index, port, opt):

            for pkt in pkt_count[index]:
                if pkt["port_no"] == port:
                    return pkt[opt]
            return 0
        # 0 : before / 1 : after
        before_target_receive = _get_value(
            target_pkt_count, 0, self.target_recv_port, 'rx_packets')

        before_target_send_1 = _get_value(
            target_pkt_count, 0, self.target_send_port_1, 'tx_packets')

        before_tester_receive_1 = _get_value(
            tester_pkt_count, 0, self.tester_recv_port_1, 'rx_packets')

        before_tester_send = _get_value(
            tester_pkt_count, 0, self.tester_send_port, 'tx_packets')

        before_target_send_2 = _get_value(
            target_pkt_count, 0, self.target_send_port_2, 'tx_packets')

        before_tester_receive_2 = _get_value(
            tester_pkt_count, 0, self.tester_recv_port_2, 'rx_packets')


        after_target_receive = _get_value(
            target_pkt_count, 1, self.target_recv_port, 'rx_packets')
        
        after_target_send_1 = _get_value(
            target_pkt_count, 1, self.target_send_port_1, 'tx_packets')
        
        after_tester_receive_1 = _get_value(
            tester_pkt_count, 1, self.tester_recv_port_1, 'rx_packets')
        
        after_tester_send = _get_value(
            tester_pkt_count, 1, self.tester_send_port, 'tx_packets')

        after_target_send_2 = _get_value(
            target_pkt_count, 1, self.target_send_port_2, 'tx_packets')
        
        after_tester_receive_2 = _get_value(
            tester_pkt_count, 1, self.tester_recv_port_2, 'rx_packets')

        if send_port != None :
            if  send_port == TESTER_SEND_PORT:
                if after_tester_send == before_tester_send:
                    log_msg = 'no send packets on %s(%d).' % (TESTER_SEND_PORT, 
                                        self.map_port[TESTER_SEND_PORT])
                elif after_target_receive == before_target_receive:
                    log_msg = 'no receive packets on %s(%d).' % (TARGET_RECV_PORT,
                                        self.map_port[TARGET_RECV_PORT])
            elif send_port == TARGET_SEND_PORT_1:
                if after_target_send_1 == before_target_send_1:
                    log_msg = 'no send packets on %s(%d).' % (TARGET_SEND_PORT_1,
                                        self.map_port[TARGET_SEND_PORT_1])
                elif after_tester_receive_1 == before_tester_receive_1:
                    log_msg = 'no receive packets on %s(%d).' % (TESTER_RECV_PORT_1,
                                        self.map_port[TESTER_RECV_PORT_1])
            elif send_port == TARGET_SEND_PORT_2:
                if after_target_send_2 == before_target_send_2:
                    log_msg = 'no send packets on %s(%d).' % (TARGET_SEND_PORT_2,
                                        self.map_port[TARGET_SEND_PORT_2])
                elif after_tester_receive_2 == before_tester_receive_2:
                    log_msg = 'no receive packets on %s(%d).' % (TESTER_RECV_PORT_2,
                                        self.map_port[TESTER_RECV_PORT_2])

        else :
            if after_tester_send == before_tester_send:
                log_msg = 'no send packets on %s(%d).' % (TESTER_SEND_PORT, 
                                        self.map_port[TESTER_SEND_PORT])
            elif after_target_receive == before_target_receive:
                log_msg = 'no receive packets on %s(%d).' % (TARGET_RECV_PORT,
                                        self.map_port[TARGET_RECV_PORT])
            elif test_type == KEY_EGRESS:
                if after_target_send_1 == before_target_send_1:
                    log_msg = 'no send packets on %s(%d).' % (TARGET_SEND_PORT_1,
                                        self.map_port[TARGET_SEND_PORT_1])
                elif after_tester_receive_1 == before_tester_receive_1:
                    log_msg = 'no receive packets on %s(%d).' % (TESTER_RECV_PORT_1,
                                        self.map_port[TESTER_RECV_PORT_1])
                else:
                    log_msg = 'receive increment packets on %s(%d).' % (TESTER_RECV_PORT_1,
                                        self.map_port[TESTER_RECV_PORT_1])
            else:
                assert test_type == KEY_PKT_IN
                log_msg = 'no packet-in.'

        raise TestFailure(self.state, detail=log_msg)

    def _test_get_match_count(self):
        xid = self.target_sw.send_table_stats()
        self.send_msg_xids.append(xid)
        self._wait()
        result = {}
        for msg in self.rcv_msgs:
            for stats in msg.body:
                result[stats.table_id] = {'lookup': stats.lookup_count,
                                          'matched': stats.matched_count}
        return result

    def _test_send_barrier(self):
        # Wait OFPBarrierReply.
        xid = self.tester_sw.send_barrier_request()
        self.send_msg_xids.append(xid)
        self._wait()
        assert len(self.rcv_msgs) == 1
        msg = self.rcv_msgs[0]
        assert isinstance(
            msg, self.tester_sw.dp.ofproto_parser.OFPBarrierReply)


    def _test_flow_unmatching_check(self, before_stats, pkt):
        # Check matched packet count.
        rcv_msgs = self._test_get_match_count()

        lookup = False
        for target_tbl_id in pkt[KEY_TBL_MISS]:
            before = before_stats[target_tbl_id]
            after = rcv_msgs[target_tbl_id]
            if before['lookup'] < after['lookup']:
                lookup = True
                if before['matched'] < after['matched']:
                    raise TestFailure(self.state)
        if not lookup:
            raise TestError(self.state)

    def _test_get_throughput(self):
        xid = self.tester_sw.send_flow_stats()
        self.send_msg_xids.append(xid)
        self._wait()

        assert len(self.rcv_msgs) == 1
        flow_stats = self.rcv_msgs[0].body
        self.logger.debug(flow_stats)
        result = {}
        for stat in flow_stats:
            if stat.cookie != THROUGHPUT_COOKIE:
                continue
            result[str(stat.match)] = (stat.byte_count, stat.packet_count)
        return (time.time(), result)

    def _test_throughput_check(self, throughputs, start, end):
        msgs = []
        elapsed_sec = end[0] - start[0]

        for throughput in throughputs:
            match = str(throughput[KEY_FLOW].match)
            # get oxm_fields of OFPMatch
            fields = dict(throughput[KEY_FLOW].match._fields2)

            if match not in start[1] or match not in end[1]:
                raise TestError(self.state, match=match)
            increased_bytes = end[1][match][0] - start[1][match][0]
            increased_packets = end[1][match][1] - start[1][match][1]

            if throughput[KEY_PKTPS]:
                key = KEY_PKTPS
                conv = 1
                measured_value = increased_packets
                unit = 'pktps'
            elif throughput[KEY_KBPS]:
                key = KEY_KBPS
                conv = 1024 / 8  # Kilobits -> bytes
                measured_value = increased_bytes
                unit = 'kbps'
            else:
                raise RyuException(
                    'An invalid key exists that is neither "%s" nor "%s".'
                    % (KEY_KBPS, KEY_PKTPS))

            expected_value = throughput[key] * elapsed_sec * conv
            margin = expected_value * THROUGHPUT_THRESHOLD
            self.logger.debug("measured_value:[%s]", measured_value)
            self.logger.debug("expected_value:[%s]", expected_value)
            self.logger.debug("margin:[%s]", margin)
            if math.fabs(measured_value - expected_value) > margin:
                msgs.append('{0} {1:.2f}{2}'.format(fields,
                            measured_value / elapsed_sec / conv, unit))

        if msgs:
            raise TestFailure(self.state, detail=', '.join(msgs))
    
    def _test_flow_count(self, sw, flows):
        if sw == self.target_sw :
            priority = TARGET_PRIORITY
        else :
            priority = TESTER_PRIORITY

        flow = flows[0] #set default
        for f in flows:
            if f["priority"] == priority: flow = f

        if len(flow) < 1 or flow["byte_count"] == 0:
                err_msg = 'SW[dpid=%s]' % dpid_lib.dpid_to_str(sw.dp.id)
        else:
            return RESULT_OK

        raise TestFailure(self.state, detail=err_msg)

    def _one_time_packet_send(self, pkt):
        self.logger.debug("send_packet:[%s]", packet.Packet(pkt[KEY_INGRESS]))
        xid = self.tester_sw.send_packet_out(pkt[KEY_INGRESS])
        self.send_msg_xids.append(xid)

    def _packet_send(self, sw, port, pkt):
        self.logger.debug("send_packet:[%s]", packet.Packet(pkt[KEY_INGRESS]))
        xid = sw.send_packet_out_port(pkt[KEY_INGRESS], port)
        self.send_msg_xids.append(xid)

    def _continuous_packet_send(self, pkt):
        assert self.ingress_event is None

        pkt_text = pkt[KEY_PACKETS]['packet_text']
        pkt_bin = pkt[KEY_PACKETS]['packet_binary']
        pktps = pkt[KEY_PACKETS][KEY_PKTPS]
        duration_time = pkt[KEY_PACKETS][KEY_DURATION_TIME]
        randomize = pkt[KEY_PACKETS]['randomize']

        self.logger.debug("send_packet:[%s]", packet.Packet(pkt_bin))
        self.logger.debug("pktps:[%d]", pktps)
        self.logger.debug("duration_time:[%d]", duration_time)

        arg = {'packet_text': pkt_text,
               'packet_binary': pkt_bin,
               'thread_counter': 0,
               'dot_span': int(CONTINUOUS_PROGRESS_SPAN /
                               CONTINUOUS_THREAD_INTVL),
               'packet_counter': float(0),
               'packet_counter_inc': pktps * CONTINUOUS_THREAD_INTVL,
               'randomize': randomize}

        try:
            self.ingress_event = hub.Event()
            tid = hub.spawn(self._send_packet_thread, arg)
            self.ingress_threads.append(tid)
            self.ingress_event.wait(duration_time)
            if self.thread_msg is not None:
                raise self.thread_msg  # pylint: disable=E0702
        finally:
            sys.stdout.write("\r\n")
            sys.stdout.flush()

    def _send_packet_thread(self, arg):
        """ Send several packets continuously. """
        if self.ingress_event is None or self.ingress_event._cond:
            return

        # display dots to express progress of sending packets
        if not arg['thread_counter'] % arg['dot_span']:
            sys.stdout.write(".")
            sys.stdout.flush()

        arg['thread_counter'] += 1

        # pile up float values and
        # use integer portion as the number of packets this thread sends
        arg['packet_counter'] += arg['packet_counter_inc']
        count = int(arg['packet_counter'])
        arg['packet_counter'] -= count

        hub.sleep(CONTINUOUS_THREAD_INTVL)

        tid = hub.spawn(self._send_packet_thread, arg)
        self.ingress_threads.append(tid)
        hub.sleep(0)
        for _ in range(count):
            if arg['randomize']:
                msg = eval('/'.join(arg['packet_text']))
                msg.serialize()
                data = msg.data
            else:
                data = arg['packet_binary']
            try:
                self.tester_sw.send_packet_out(data)
            except Exception as err:
                self.thread_msg = err
                self.ingress_event.set()
                break

class TestPatterns(stringify.StringifyMixin):
    """ The class is used to parse test item of json format. """
    def __init__(self, map_port, req, logger, parse_tests=True):
        super(TestPatterns, self).__init__()
        self.logger = logger
        self.description = None
        self.test_items = []
        self.map_port = map_port
        self._get_tests(req.test_item, parse_tests)

    def _normalize_test_json(self, val):
        def __replace_port_name(k, v):
            for port_name in [
                TARGET_RECV_PORT, TARGET_SEND_PORT_1,
                TARGET_SEND_PORT_2, TESTER_SEND_PORT,
                TESTER_RECV_PORT_1, TESTER_RECV_PORT_2]:
                if v[k] == port_name:
                    v[k] = self.map_port[port_name]

        if isinstance(val, dict):
            for k, v in val.iteritems():
                if k == "OFPActionOutput":
                    if 'port' in v:
                        __replace_port_name("port", v)
                elif k == "OXMTlv":
                    if v.get("field", "") == "in_port":
                        __replace_port_name("value", v)
                self._normalize_test_json(v)
        elif isinstance(val, list):
            for v in val:
                self._normalize_test_json(v)

    def _get_tests(self, item, parse_tests):
        try:
            json_list = item
            for test_json in json_list:
                if isinstance(test_json, unicode):
                    self.description = test_json
                else:
                    self._normalize_test_json(test_json)
                      
                    self.test_items.append(TestItem(self.map_port, 
                                            test_json,
                                            parse_tests))
        except (ValueError, TypeError) as e:
            result = (TEST_ITEM_ERROR %
                          {'detail': e.message})
            self.logger.warning(result)
            raise e

class TestItem(stringify.StringifyMixin):
    def __init__(self, map_port, test_json, parse_tests):
        super(TestItem, self).__init__()
        self.parse_tests = parse_tests
        self.map_port = map_port
        (self.description,
         self.prerequisite,
         self.tests,
         self.tests_str) = self._parse_test(test_json)

    def _parse_test(self, buf):
        def _decode_list(data):
            rv = []
            for item in data:
                if isinstance(item, unicode):
                    item = item.encode('utf-8')
                elif isinstance(item, list):
                    item = _decode_list(item)
                elif isinstance(item, dict):
                    item = _decode_dict(item)
                rv.append(item)
            return rv

        def _decode_dict(data):
            rv = {}
            for key, value in data.iteritems():
                if isinstance(key, unicode):
                    key = key.encode('utf-8')
                if isinstance(value, unicode):
                    value = value.encode('utf-8')
                elif isinstance(value, list):
                    value = _decode_list(value)
                elif isinstance(value, dict):
                    value = _decode_dict(value)
                rv[key] = value
            return rv

        def __test_pkt_from_json(test):
            data = eval('/'.join(test))
            data.serialize()
            return str(data.data)

        def __test_pkt_str_from_json(test):
            return _decode_list(test)

        def __normalize_match(ofproto, match, auto_in_port=False):
            match_json = match.to_jsondict()
            oxm_fields = match_json['OFPMatch']['oxm_fields']
            fields = []
            flag = True
            for field in oxm_fields:
                if auto_in_port == True and field.has_key("OXMTlv"):
                    if field["OXMTlv"]["field"] == "in_port":
                        flag = False

                field_obj = ofproto.oxm_from_jsondict(field)
                field_obj = ofproto.oxm_normalize_user(*field_obj)
                fields.append(field_obj)
            if auto_in_port == True and flag:
                field = {"OXMTlv": {"field":"in_port", 
                    "value": self.map_port[TARGET_RECV_PORT]}}
                field_obj = ofproto.oxm_from_jsondict(field)
                field_obj = ofproto.oxm_normalize_user(*field_obj)
                fields.append(field_obj)

            return match.__class__(_ordered_fields=fields)

        def __normalize_action(ofproto, action):
            action_json = action.to_jsondict()
            field = action_json['OFPActionSetField']['field']
            field_obj = ofproto.oxm_from_jsondict(field)
            field_obj = ofproto.oxm_normalize_user(*field_obj)
            kwargs = {}
            kwargs[field_obj[0]] = field_obj[1]
            return action.__class__(**kwargs)

        def __replace_port_name(desc):
            for port_name in [
                TARGET_RECV_PORT, TARGET_SEND_PORT_1,
                TARGET_SEND_PORT_2, TESTER_SEND_PORT,
                TESTER_RECV_PORT_1, TESTER_RECV_PORT_2]:
                desc = desc.replace(port_name, str(self.map_port[port_name]))
            return desc
                
        # get ofproto modules using user-specified versions
        (target_ofproto, target_parser) = ofproto_protocol._versions[
            OfTester.target_ver]
        (tester_ofproto, tester_parser) = ofproto_protocol._versions[
            OfTester.tester_ver]
        target_dp = DummyDatapath()
        target_dp.ofproto = target_ofproto
        target_dp.ofproto_parser = target_parser
        tester_dp = DummyDatapath()
        tester_dp.ofproto = tester_ofproto
        tester_dp.ofproto_parser = tester_parser

        # parse 'description'
        description = __replace_port_name(
                            buf.get(KEY_DESC))

        # parse 'prerequisite'
        prerequisite = []

        if KEY_PREREQ not in buf:
            raise ValueError('a test requires a "%s" block' % KEY_PREREQ)

        allowed_mod = [KEY_FLOW, KEY_METER, KEY_GROUP]
        for flow in buf[KEY_PREREQ]:
            key, value = flow.popitem()
            if key not in allowed_mod:
                raise ValueError(
                    '"%s" block allows only the followings: %s' % (
                        KEY_PREREQ, allowed_mod))
            cls = getattr(target_parser, key)
            msg = cls.from_jsondict(value, datapath=target_dp)
            msg.version = target_ofproto.OFP_VERSION
            msg.msg_type = msg.cls_msg_type
            msg.xid = 0
            if isinstance(msg, target_parser.OFPFlowMod):
                # normalize OFPMatch
                msg.match = __normalize_match(target_ofproto, msg.match, 
                                        auto_in_port=True)

                # normalize OFPActionSetField
                insts = []
                for inst in msg.instructions:
                    if isinstance(inst, target_parser.OFPInstructionActions):
                        acts = []
                        for act in inst.actions:
                            if isinstance(
                                    act, target_parser.OFPActionSetField):
                                act = __normalize_action(target_ofproto, act)
                            acts.append(act)
                        inst = target_parser.OFPInstructionActions(
                            inst.type, actions=acts)
                    insts.append(inst)
                msg.instructions = insts
            elif isinstance(msg, target_parser.OFPGroupMod):
                # normalize OFPActionSetField
                buckets = []
                for bucket in msg.buckets:
                    acts = []
                    for act in bucket.actions:
                        if isinstance(act, target_parser.OFPActionSetField):
                            act = __normalize_action(target_ofproto, act)
                        acts.append(act)
                    bucket = target_parser.OFPBucket(
                        weight=bucket.weight,
                        watch_port=bucket.watch_port,
                        watch_group=bucket.watch_group,
                        actions=acts)
                    buckets.append(bucket)
                msg.buckets = buckets
            msg.serialize()
            prerequisite.append(msg)

        if self.parse_tests == False:
            return (description, prerequisite, [], [])

        # parse 'tests'
        tests = []
        tests_str = []
        if KEY_TESTS not in buf:
            raise ValueError('a test requires a "%s" block.' % KEY_TESTS)

        for test in buf[KEY_TESTS]:
            if len(test) != 2:
                raise ValueError(
                    '"%s" block requires "%s" field and one of "%s" or "%s"'
                    ' or "%s" field.' % (KEY_TESTS, KEY_INGRESS, KEY_EGRESS,
                                         KEY_PKT_IN, KEY_TBL_MISS))
            test_pkt = {}
            test_pkt_str = {}
            # parse 'ingress'
            if KEY_INGRESS not in test:
                raise ValueError('a test requires "%s" field.' % KEY_INGRESS)
            if isinstance(test[KEY_INGRESS], list):
                test_pkt[KEY_INGRESS] = __test_pkt_from_json(test[KEY_INGRESS])
                test_pkt_str[KEY_INGRESS] = __test_pkt_str_from_json(test[KEY_INGRESS])
            elif isinstance(test[KEY_INGRESS], dict):
                test_pkt[KEY_PACKETS] = {
                    'packet_text': test[KEY_INGRESS][KEY_PACKETS][KEY_DATA],
                    'packet_binary': __test_pkt_from_json(
                        test[KEY_INGRESS][KEY_PACKETS][KEY_DATA]),
                    KEY_DURATION_TIME: test[KEY_INGRESS][KEY_PACKETS].get(
                        KEY_DURATION_TIME, DEFAULT_DURATION_TIME),
                    KEY_PKTPS: test[KEY_INGRESS][KEY_PACKETS].get(
                        KEY_PKTPS, DEFAULT_PKTPS),
                    'randomize': True in [
                        line.find('randint') != -1
                        for line in test[KEY_INGRESS][KEY_PACKETS][KEY_DATA]]}
                
                test_pkt_str[KEY_PACKETS] = {
                    'packet_text': test[KEY_INGRESS][KEY_PACKETS][KEY_DATA],
                    'packet_binary': __test_pkt_str_from_json(
                        test[KEY_INGRESS][KEY_PACKETS][KEY_DATA]),
                    KEY_DURATION_TIME: test[KEY_INGRESS][KEY_PACKETS].get(
                        KEY_DURATION_TIME, DEFAULT_DURATION_TIME),
                    KEY_PKTPS: test[KEY_INGRESS][KEY_PACKETS].get(
                        KEY_PKTPS, DEFAULT_PKTPS),
                    'randomize': True in [
                        line.find('randint') != -1
                        for line in test[KEY_INGRESS][KEY_PACKETS][KEY_DATA]]}
                
            else:
                raise ValueError('invalid format: "%s" field' % KEY_INGRESS)
            # parse 'egress' or 'PACKET_IN' or 'table-miss'
            if KEY_EGRESS in test:
                if isinstance(test[KEY_EGRESS], list):
                    test_pkt[KEY_EGRESS] = __test_pkt_from_json(
                        test[KEY_EGRESS])
                    test_pkt_str[KEY_EGRESS] = __test_pkt_str_from_json(
                        test[KEY_EGRESS])
                elif isinstance(test[KEY_EGRESS], dict):
                    throughputs = []
                    for throughput in test[KEY_EGRESS][KEY_THROUGHPUT]:
                        one = {}
                        mod = {'match': {'OFPMatch': throughput[KEY_MATCH]}}
                        cls = getattr(tester_parser, KEY_FLOW)
                        msg = cls.from_jsondict(
                            mod, datapath=tester_dp,
                            cookie=THROUGHPUT_COOKIE,
                            priority=THROUGHPUT_PRIORITY)
                        msg.match = __normalize_match(
                            tester_ofproto, msg.match, auto_in_port=False)
                        one[KEY_FLOW] = msg
                        one[KEY_KBPS] = throughput.get(KEY_KBPS)
                        one[KEY_PKTPS] = throughput.get(KEY_PKTPS)
                        if not bool(one[KEY_KBPS]) != bool(one[KEY_PKTPS]):
                            raise ValueError(
                                '"%s" requires either "%s" or "%s".' % (
                                    KEY_THROUGHPUT, KEY_KBPS, KEY_PKTPS))
                        throughputs.append(one)
                    test_pkt[KEY_THROUGHPUT] = throughputs
                else:
                    raise ValueError('invalid format: "%s" field' % KEY_EGRESS)
            elif KEY_PKT_IN in test:
                test_pkt[KEY_PKT_IN] = __test_pkt_from_json(test[KEY_PKT_IN])
                test_pkt_str[KEY_PKT_IN] = __test_pkt_str_from_json(test[KEY_PKT_IN])
            elif KEY_TBL_MISS in test:
                test_pkt[KEY_TBL_MISS] = test[KEY_TBL_MISS]

            tests.append(test_pkt)
            tests_str.append(test_pkt_str)

        return (description, prerequisite, tests, tests_str)


class OpenFlowSw(object):

    def __init__(self, dp, logger, req):
        super(OpenFlowSw, self).__init__()
        self.dp = dp
        self.logger = logger
        self.tester_send_port = req.tester_send_port

    def send_msg(self, msg):
        if isinstance(self.dp, DummyDatapath):
            raise TestError(STATE_DISCONNECTED)
        msg.xid = None
        self.dp.set_xid(msg)
        self.dp.send_msg(msg)
        return msg.xid

    def get_flow(self, in_port=None, out_port=None, priority=None):
        """ Add flow. """

        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser

        if in_port == None:
            match = parser.OFPMatch()
            actions = []
        else:
            match = parser.OFPMatch(in_port=in_port)
            max_len = (0 if out_port != ofp.OFPP_CONTROLLER
                   else ofp.OFPCML_MAX)
            actions = [parser.OFPActionOutput(out_port, max_len)]
        
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if priority == None:
            mod = parser.OFPFlowMod(self.dp, cookie=0,
                                command=ofp.OFPFC_ADD,
                                match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(self.dp, cookie=0,
                                priority=priority,
                                command=ofp.OFPFC_ADD,
                                match=match, instructions=inst)
        return mod

    def del_flows(self, cookie=0):
        """ Delete all flow except default flow. """
        
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        cookie_mask = 0
        if cookie:
            cookie_mask = 0xffffffffffffffff
        mod = parser.OFPFlowMod(self.dp,
                                cookie=cookie,
                                cookie_mask=cookie_mask,
                                table_id=ofp.OFPTT_ALL,
                                command=ofp.OFPFC_DELETE,
                                out_port=ofp.OFPP_ANY,
                                out_group=ofp.OFPG_ANY)
        return self.send_msg(mod)

    def del_meters(self):
        """ Delete all meter entries. """
        
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        mod = parser.OFPMeterMod(self.dp,
                                 command=ofp.OFPMC_DELETE,
                                 flags=0,
                                 meter_id=ofp.OFPM_ALL)
        return self.send_msg(mod)

    def del_groups(self):
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        mod = parser.OFPGroupMod(self.dp,
                                 command=ofp.OFPGC_DELETE,
                                 type_=0,
                                 group_id=ofp.OFPG_ALL)
        return self.send_msg(mod)

    def send_barrier_request(self):
        """ send a BARRIER_REQUEST message."""
        parser = self.dp.ofproto_parser
        req = parser.OFPBarrierRequest(self.dp)
        return self.send_msg(req)

    def send_port_stats(self):
        """ Get port stats."""
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        flags = 0
        req = parser.OFPPortStatsRequest(self.dp, flags, ofp.OFPP_ANY)
        return self.send_msg(req)

    def send_port_desc_stats(self):
        """ Get port stats."""
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        flags = 0
        req = parser.OFPPortDescStatsRequest(self.dp, 0)
        return self.send_msg(req)

    def send_flow_stats(self):
        """ Get all flow. """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        req = parser.OFPFlowStatsRequest(self.dp, 0, ofp.OFPTT_ALL,
                                         ofp.OFPP_ANY, ofp.OFPG_ANY,
                                         0, 0, parser.OFPMatch())
        return self.send_msg(req)


    def send_flow_stats_for_target(self, cookie):
        """ Get all flow. """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        req = parser.OFPFlowStatsRequest(self.dp, 0, ofp.OFPTT_ALL,
                                         ofp.OFPP_ANY, ofp.OFPG_ANY,
                                         0, 0, parser.OFPMatch())
        return self.send_msg(req)

    def send_flow_stats_for_tester(self, cookie):
        """ Get all flow. """
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        req = parser.OFPFlowStatsRequest(self.dp, 0, ofp.OFPTT_ALL,
                                         ofp.OFPP_ANY, ofp.OFPG_ANY,
                                         0, 0, parser.OFPMatch())
        return self.send_msg(req)

    def send_meter_config_stats(self):
        """ Get all meter. """
        parser = self.dp.ofproto_parser
        stats = parser.OFPMeterConfigStatsRequest(self.dp)
        return self.send_msg(stats)

    def send_group_desc_stats(self):
        parser = self.dp.ofproto_parser
        stats = parser.OFPGroupDescStatsRequest(self.dp)
        return self.send_msg(stats)

    def send_table_stats(self):
        """ Get table stats. """
        parser = self.dp.ofproto_parser
        req = parser.OFPTableStatsRequest(self.dp, 0)
        return self.send_msg(req)

    def send_packet_out(self, data):
        """ send a PacketOut message."""
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        actions = [parser.OFPActionOutput(self.tester_send_port)]
        out = parser.OFPPacketOut(
            datapath=self.dp, buffer_id=ofp.OFP_NO_BUFFER,
            data=data, in_port=ofp.OFPP_CONTROLLER, actions=actions)
        return self.send_msg(out) 

    def send_packet_out_port(self, data, port):
        """ send a PacketOut message."""
        ofp = self.dp.ofproto
        parser = self.dp.ofproto_parser
        actions = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(
            datapath=self.dp, buffer_id=ofp.OFP_NO_BUFFER,
            data=data, in_port=ofp.OFPP_CONTROLLER, actions=actions)
        return self.send_msg(out) 

class DummyDatapath(object):
    def __init__(self):
        self.ofproto = ofproto_v1_3
        self.ofproto_parser = ofproto_v1_3_parser

    def set_xid(self, _):
        pass

    def send_msg(self, _):
        pass
