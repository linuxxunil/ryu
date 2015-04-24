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
from ryu.tests.switch.api import *
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
#
# test a queue to the switches
# POST /tests/switch
#
# request body format:
#  {"sw_target_version" : "<openflow13 or openflow14>",
#   "sw_target_dpid" : "<dpid>",
#   "sw_target_recv_port"   : "<int>",
#   "sw_target_send_port_1" : "<int>",
#   "sw_target_send_port_2" : "<int>",
#   "sw_tester_dpid" : "<dpid>",
#   "sw_tester_recv_port" : "<int>",
#   "sw_tester_send_port_1" : "<int>",
#   "sw_tester_send_port_2" : "<int>"
#   "sw_test_item : "[ryu test format]"}
#
# where
# <dpid>: datapath id in 16 hex


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

