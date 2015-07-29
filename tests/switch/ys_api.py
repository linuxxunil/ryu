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

from ryu.base import app_manager
from ryu.tests.switch import ys_event as event

def do_test_item(app, item, parse_tests=True):
	rep = app.send_request(event.EventTestItemRequest(item, parse_tests))
	return rep.result

def get_test_item(app):
	rep = app.send_request(event.EventTestItemResultRequest())
	return rep.result

def stop_test_item(app):
	rep = app.send_request(event.EventTestItemStopRequest())
	return rep.result

def do_check_link(app, item):
	rep = app.send_request(event.EventCheckLinkRequest(item))
	return rep.result

def get_check_link(app):
	rep = app.send_request(event.EventCheckLinkResultRequest())
	return rep.result

def stop_check_link(app):
	rep = app.send_request(event.EventCheckLinkStopRequest())
	return rep.result



app_manager.require_app('ryu.tests.switch.ys_tester', api_style=True)
