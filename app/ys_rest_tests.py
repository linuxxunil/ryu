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

                      +-------------------------+
           +----------|     target sw           | The switch to be tested
           |          +-------------------------+
    +------------+      (1) (2) (3) (4) (5) (6)
    | controller |       |   |   |   |   |   |
    +------------+       -----   -----   -----
          
"""

# REST API for tester configuration
#
# get test item status
# GET /tests/switch/item
#
# stop test item
# DELETE /tests/switch/item
#
# start test item
# POST /tests/switch/item
#
# request body format:
#  {"target_version" : "<openflow13 or openflow14>",
#   "target_dpid" : "<int>",
#   "target_recv_port"   : "<int>",
#   "target_send_port_1" : "<int>",
#   "target_send_port_2" : "<int>",
#   "tester_dpid" : "<int>",
#   "tester_recv_port" : "<int>",
#   "tester_send_port_1" : "<int>",
#   "tester_send_port_2" : "<int>",
#   "test_item : "[ryu test format]"}
#
# get test flowentry status
# GET /tests/switch/item/flowentry
#
# stop test flowentry 
# DELETE /tests/switch/item/flowentry
#
# start test flowentry
# POST /tests/switch/item/flowentry
#
# request body format:
#  {"target_version"     : "<openflow13 or openflow14>",
#   "target_dpid"        : "<int>",
#   "target_recv_port"   : "<int>",
#   "target_send_port_1" : "<int>",
#   "target_send_port_2" : "<int>",
#   "tester_version"     : "<openflow13 or openflow14>",
#   "tester_dpid"        : "<int>",
#   "tester_recv_port"   : "<int>",
#   "tester_send_port_1" : "<int>",
#   "tester_send_port_2" : "<int>",
#   "test_item : "[ryu test format]"}
#
# get test link status
# GET /tests/switch/check/link
#
# stop test link 
# DELETE /tests/switch/check/link
#
# start test link
# POST /tests/switch/check/link
#
# request body format:
#  {"target_version"     : "<openflow13 or openflow14>",
#   "target_dpid"        : "<int>",
#   "target_recv_port"   : "<int>",
#   "target_send_port_1" : "<int>",
#   "target_send_port_2" : "<int>",
#   "tester_version"     : "<openflow13 or openflow14>",
#   "tester_dpid"        : "<int>",
#   "tester_recv_port"   : "<int>",
#   "tester_send_port_1" : "<int>",
#   "tester_send_port_2" : "<int>"}

'''
Example :
1. get test item status
curl http://127.0.0.1:8080/tests/switch/item

2. stop test item
curl -X DELETE http://127.0.0.1:8080/tests/switch/item

3. start test item
curl -X POST -d '{"tester_version":"openflow13","tester_dpid":1,"tester_send_port":1,"tester_recv_port_1":3,"tester_recv_port_2":6,"target_version":"openflow13","target_dpid":1,"target_recv_port":2,"target_send_port_1":4,"target_send_port_2":5,"test_item":["action: 00_OUTPUT",{"description":"ethernet/ipv4/tcp-->'actions=output:2'","prerequisite":[{"OFPFlowMod":{"table_id":0,"instructions":[{"OFPInstructionActions":{"actions":[{"OFPActionOutput":{"port":2}}],"type":4}}]}}],"tests":[{"ingress":["ethernet(dst='22:22:22:22:22:22', src='12:11:11:11:11:11', ethertype=2048)","ipv4(tos=32, proto=6, src='192.168.10.10', dst='192.168.20.20', ttl=64)","tcp(dst_port=2222, option=str('\\\\x00' * 4), src_port=11111)","'\\\\x01\\\\x02\\\\x03\\\\x04\\\\x05\\\\x06\\\\x07\\\\x08\\\\t\\\\n\\\\x0b\\\\x0c\\\\r\\\\x0e\\\\x0f\\\\x10\\\\x11\\\\x12\\\\x13\\\\x14\\\\x15\\\\x16\\\\x17\\\\x18\\\\x19\\\\x1a\\\\x1b\\\\x1c\\\\x1d\\\\x1e\\\\x1f'"],"egress":["ethernet(dst='22:22:22:22:22:22', src='12:11:11:11:11:11', ethertype=2048)","ipv4(tos=32, proto=6, src='192.168.10.10', dst='192.168.20.20', ttl=64)","tcp(dst_port=2222, option=str('\\\\x00' * 4), src_port=11111)","'\\\\x01\\\\x02\\\\x03\\\\x04\\\\x05\\\\x06\\\\x07\\\\x08\\\\t\\\\n\\\\x0b\\\\x0c\\\\r\\\\x0e\\\\x0f\\\\x10\\\\x11\\\\x12\\\\x13\\\\x14\\\\x15\\\\x16\\\\x17\\\\x18\\\\x19\\\\x1a\\\\x1b\\\\x1c\\\\x1d\\\\x1e\\\\x1f'"]}]}]}' http://127.0.0.1:8080/tests/switch/item

4. get test flowentry status
curl http://127.0.0.1:8080/tests/switch/item/flowentry

5. stop test flowentry 
curl -X DELETE http://127.0.0.1:8080/tests/switch/item/flowentry

6. start test flowentry
curl -X POST -d '{"tester_version":"openflow13","tester_dpid":1,"tester_send_port":1,"tester_recv_port_1":3,"tester_recv_port_2":6,"target_version":"openflow13","target_dpid":1,"target_recv_port":2,"target_send_port_1":4,"target_send_port_2":5,"test_item":["action: 00_OUTPUT",{"description":"ethernet/ipv4/tcp-->'actions=output:2'","prerequisite":[{"OFPFlowMod":{"table_id":0,"instructions":[{"OFPInstructionActions":{"actions":[{"OFPActionOutput":{"port":2}}],"type":4}}]}}],"tests":[{"ingress":["ethernet(dst='22:22:22:22:22:22', src='12:11:11:11:11:11', ethertype=2048)","ipv4(tos=32, proto=6, src='192.168.10.10', dst='192.168.20.20', ttl=64)","tcp(dst_port=2222, option=str('\\\\x00' * 4), src_port=11111)","'\\\\x01\\\\x02\\\\x03\\\\x04\\\\x05\\\\x06\\\\x07\\\\x08\\\\t\\\\n\\\\x0b\\\\x0c\\\\r\\\\x0e\\\\x0f\\\\x10\\\\x11\\\\x12\\\\x13\\\\x14\\\\x15\\\\x16\\\\x17\\\\x18\\\\x19\\\\x1a\\\\x1b\\\\x1c\\\\x1d\\\\x1e\\\\x1f'"],"egress":["ethernet(dst='22:22:22:22:22:22', src='12:11:11:11:11:11', ethertype=2048)","ipv4(tos=32, proto=6, src='192.168.10.10', dst='192.168.20.20', ttl=64)","tcp(dst_port=2222, option=str('\\\\x00' * 4), src_port=11111)","'\\\\x01\\\\x02\\\\x03\\\\x04\\\\x05\\\\x06\\\\x07\\\\x08\\\\t\\\\n\\\\x0b\\\\x0c\\\\r\\\\x0e\\\\x0f\\\\x10\\\\x11\\\\x12\\\\x13\\\\x14\\\\x15\\\\x16\\\\x17\\\\x18\\\\x19\\\\x1a\\\\x1b\\\\x1c\\\\x1d\\\\x1e\\\\x1f'"]}]}]}' http://127.0.0.1:8080/tests/switch/item

7. get test link status
curl http://127.0.0.1:8080/tests/switch/check/link

8. stop test link 
curl -X DELETE http://127.0.0.1:8080/tests/switch/check/link

9. start test link
curl -X POST -d '{"tester_version":"openflow13","tester_dpid":1,"tester_send_port":1,"tester_recv_port_1":3,"tester_recv_port_2":6,"target_version":"openflow13","target_dpid":1,"target_recv_port":2,"target_send_port_1":4,"target_send_port_2":5}' http://127.0.0.1:8080/tests/switch/check/link

'''


class TestsAPI(app_manager.RyuApp):
    _CONTEXTS = {
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(TestsAPI, self).__init__(*args, **kwargs)

        wsgi = kwargs['wsgi']
        wsgi.register(TestsController, {'tests_api_app': self})


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

class TestsController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(TestsController, self).__init__(req, link, data, **config)
        self.test_api_app = data['tests_api_app']

    

    @route('tests', '/tests/switch/item',
           methods=['POST'])
    def _do_test_item(self, req, **kwargs):
        result = []
        content = json.loads(req.body) if req.body else {}
        result = do_test_item(self.test_api_app, content)
        body = json.dumps(result)
        return Response(content_type='application/json', body=body)    

    @route('tests', '/tests/switch/item',
           methods=['GET'])
    def _get_test_item(self, req, **kwargs):
        result = get_test_item(self.test_api_app)        
        #print result["report"][0]["operating"]
        body = json.dumps(result)
        return Response(content_type='application/json', body=body)


    @route('tests', '/tests/switch/item',
           methods=['DELETE'])
    def _stop_test_item(self, req, **kwargs):
        result = stop_test_item(self.test_api_app)
        body = json.dumps(result)
        return Response(content_type='application/json', body=body)

    
    @route('tests', '/tests/switch/item/flowentry',
           methods=['POST'])
    def _do_test_flowentry(self, req, **kwargs):
        content = json.loads(req.body) if req.body else {}
        result  = do_test_item(self.test_api_app, content, False)
        body = json.dumps(result)
        return Response(content_type='application/json', body=body)

    @route('tests', '/tests/switch/item/flowentry',
           methods=['GET'])
    def _get_test_flowentry(self, req, **kwargs):
        result = get_test_item(self.test_api_app)        
        body = json.dumps(result)
        return Response(content_type='application/json', body=body)


    @route('tests', '/tests/switch/item/flowentry',
           methods=['DELETE'])
    def _stop_test_flowentry(self, req, **kwargs):
        result = stop_test_item(self.test_api_app)
        body = json.dumps(result)
        return Response(content_type='application/json', body=body)
    
    @route('tests', '/tests/switch/check/link',
           methods=['POST'])
    def _do_check_link(self, req, **kwargs):
        content = json.loads(req.body) if req.body else {}
        result = do_check_link(self.test_api_app, content)
        body = json.dumps(result)
        return Response(content_type='application/json', body=body)


    @route('tests', '/tests/switch/check/link',
           methods=['GET'])
    def _get_check_link(self, req, **kwargs):
        result = get_check_link(self.test_api_app)        
        body = json.dumps(result)
        return Response(content_type='application/json', body=body)

    @route('tests', '/tests/switch/check/link',
           methods=['DELETE'])
    def _stop_check_link(self, req, **kwargs):
        result = stop_check_link(self.test_api_app)
        body = json.dumps(result)
        return Response(content_type='application/json', body=body)

