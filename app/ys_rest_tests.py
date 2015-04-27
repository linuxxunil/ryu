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

import json
from webob import Response

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.lib import dpid as dpid_lib
from ryu.tests.switch.ys_api import *
from collections import OrderedDict

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

# REST API for tester configuration
#
# get test item status
# GET /tests/switch/item
#
# stop test status
# DELETE /tests/switch/item
#
# start test item
# POST /tests/switch/item
#
# request body format:
#  {"sw_target_version" : "<openflow13 or openflow14>",
#   "sw_target_dpid" : "<int>",
#   "sw_target_recv_port"   : "<int>",
#   "sw_target_send_port_1" : "<int>",
#   "sw_target_send_port_2" : "<int>",
#   "sw_tester_dpid" : "<int>",
#   "sw_tester_recv_port" : "<int>",
#   "sw_tester_send_port_1" : "<int>",
#   "sw_tester_send_port_2" : "<int>"
#   "sw_test_item : "[ryu test format]"}
# 
# Example :
'''
{"target_version":"openflow13","target_dpid":1,"target_recv_port":1,
"target_send_port_1":2,"target_send_port_2":3,"tester_version":"openflow13",
"tester_dpid":2,"tester_send_port":1,"tester_recv_port_1":2,"tester_recv_port_2":3,
"test_item":["action: 19_PUSH_MPLS",{"description":"ethernet/ipv4/tcp-->'eth_type=0x0800,actions=push_mpls:0x8847,output:2'",
"prerequisite":[{"OFPFlowMod":{"table_id":0,"match":{"OFPMatch":{"oxm_fields":[{"OXMTlv":{"field":"eth_type","value":2048}}]}},
"instructions":[{"OFPInstructionActions":{"actions":[{"OFPActionPushMpls":{"ethertype":34887}},
{"OFPActionOutput":{"port":2}}],"type":4}}]}}],"tests":[{"ingress":["ethernet(dst='22:22:22:22:22:22', src='12:11:11:11:11:11', ethertype=2048)",
"ipv4(tos=32, proto=6, src='192.168.10.10', dst='192.168.20.20', ttl=64)","tcp(dst_port=2222, option=str('\\x00' * 4), src_port=11111)",
"'\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\t\\n\\x0b\\x0c\\r\\x0e\\x0f\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f'"],
"egress":["ethernet(dst='22:22:22:22:22:22', src='12:11:11:11:11:11', ethertype=34887)","mpls(ttl=64)","ipv4(tos=32, proto=6, src='192.168.10.10', dst='192.168.20.20', ttl=64)",
"tcp(dst_port=2222, option=str('\\x00' * 4), src_port=11111)","'\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\t\\n\\x0b\\x0c\\r\\x0e\\x0f\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f'"]}]},
{"description":"ethernet/ipv6/tcp-->'eth_type=0x86dd,actions=push_mpls:0x8847,output:2'",
"prerequisite":[{"OFPFlowMod":{"table_id":0,"match":{"OFPMatch":{"oxm_fields":[{"OXMTlv":{"field":"eth_type","value":34525}}]}},
"instructions":[{"OFPInstructionActions":{"actions":[{"OFPActionPushMpls":{"ethertype":34887}},{"OFPActionOutput":{"port":2}}],"type":4}}]}}],
"tests":[{"ingress":["ethernet(dst='22:22:22:22:22:22', src='12:11:11:11:11:11', ethertype=34525)",
"ipv6(dst='20::20', flow_label=100, src='10::10', nxt=6, hop_limit=64, traffic_class=32)","tcp(dst_port=2222, option=str('\\x00' * 4), src_port=11111)",
"'\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\t\\n\\x0b\\x0c\\r\\x0e\\x0f\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f'"],
"egress":["ethernet(dst='22:22:22:22:22:22', src='12:11:11:11:11:11', ethertype=34887)","mpls(ttl=64)",
"ipv6(dst='20::20', flow_label=100, src='10::10', nxt=6, hop_limit=64, traffic_class=32)",
"tcp(dst_port=2222, option=str('\\x00' * 4), src_port=11111)","'\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\t\\n\\x0b\\x0c\\r\\x0e\\x0f\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f'"]}]},
{"description":"ethernet/arp-->'eth_type=0x0806,actions=push_mpls:0x8847,output:2'","prerequisite":[{"OFPFlowMod":{"table_id":0,"match":{"OFPMatch":{"oxm_fields":[{"OXMTlv":{"field":"eth_type","value":2054}}]}},
"instructions":[{"OFPInstructionActions":{"actions":[{"OFPActionPushMpls":{"ethertype":34887}},{"OFPActionOutput":{"port":2}}],"type":4}}]}}],"tests":[{"ingress":["ethernet(dst='22:22:22:22:22:22', src='12:11:11:11:11:11', ethertype=2054)",
"arp(dst_ip='192.168.20.20',dst_mac='22:22:22:22:22:22', opcode=1, src_ip='192.168.10.10',src_mac='12:11:11:11:11:11')","str('\\x00' * (60 - 42))"],"egress":["ethernet(dst='22:22:22:22:22:22', src='12:11:11:11:11:11', ethertype=34887)",
"mpls(ttl=0)","arp(dst_ip='192.168.20.20',dst_mac='22:22:22:22:22:22', opcode=1, src_ip='192.168.10.10',src_mac='12:11:11:11:11:11')","str('\\x00' * (60 - 42))"]}]}]}
'''


class TestsAPI(app_manager.RyuApp):
    _CONTEXTS = {
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(TestsAPI, self).__init__(*args, **kwargs)

        wsgi = kwargs['wsgi']
        wsgi.register(TestsController, {'tests_api_app': self})


class TestsController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(TestsController, self).__init__(req, link, data, **config)
        self.test_api_app = data['tests_api_app']

    @route('tests', '/tests/switch/item',
           methods=['POST'])
    def _do_test_item(self, req, **kwargs):
        result = []
        content = json.loads(req.body) if req.body else {}
        status, description, target_dpid  = do_test_item(self.test_api_app, content)
        
        result.append("status")
        result.append(status)
        result.append("description")
        result.append(description)
        result.append("target_dpid")
        result.append(target_dpid)
        
        body = json.dumps(dict(result[i:i+2] for i in range(0, len(result), 2)))
        return Response(content_type='application/json', body=body)

    @route('tests', '/tests/switch/item',
           methods=['GET'])
    def _get_test_result(self, req, **kwargs):
        tmp = {}
        tmp["result"], tmp["target_dpid"], tmp["state"], tmp["item"] = get_test_item(self.test_api_app)        
        body = json.dumps(tmp)
        return Response(content_type='application/json', body=body)

    @route('tests', '/tests/switch/item',
           methods=['DELETE'])
    def _stop_test_result(self, req, **kwargs):
        stop_test_item(self.test_api_app)
        body = ""
        return Response(content_type='application/json', body=body)

