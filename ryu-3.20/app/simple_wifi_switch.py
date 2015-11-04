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
from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib import dpid as dpid_lib
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import WSGIApplication
from ryu.exception import RyuException
from ryu.exception import OFPUnknownVersion
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from webob import Response

import sqlite3

# =============================
#          REST API
# =============================
#
# * Insert one mac to database
# POST /guest/database/mac/add
#  
# parameter = {"mac":["00:01:02:03:02:05","00:02:04:08:10:12"]}
#
# * Delete one mac from database
# POST /guest/database/mac/del
# 
# parameter = {"mac":["00:01:02:03:02:05","00:02:04:08:10:12"]}
#
# * Delete all mac from database
# DELETE /guest/database/mac/del/all
#
# * Get all mac from database
# GET /guest/database/mac
#
# * Set server port
# POST /guest/switch/server/port
# 
# parameter = {"dpid":1,"port":[4]}
#
UINT16_MAX = 0xffff
UINT32_MAX = 0xffffffff
UINT64_MAX = 0xffffffffffffffff
REST_RESULT = 'result'
REST_DETAILS = 'details'
REST_NG = 'failure'

class NotFoundError(RyuException):
    message = 'Router SW is not connected. : switch_id=%(switch_id)s'


class CommandFailure(RyuException):
    pass


class RestSwitchAPI(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    _CONTEXTS = {'dpset': dpset.DPSet,
                 'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(RestSwitchAPI, self).__init__(*args, **kwargs)

        # logger configure
        SwitchController.set_logger(self.logger)

        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {'waiters': self.waiters}

        mapper = wsgi.mapper
        wsgi.registory['SwitchController'] = self.data
        requirements = {}

        # For database
        path = '/guest/database/mac/add'
        mapper.connect('router', path, controller=SwitchController,
                        requirements=requirements,
                        action='add_mac',
                        conditions=dict(method=['POST']))

        path = '/guest/database/mac/del'
        mapper.connect('router', path, controller=SwitchController,
                        requirements=requirements,
                        action='del_mac',
                        conditions=dict(method=['POST']))

        path = '/guest/database/mac/del/all'
        mapper.connect('router', path, controller=SwitchController,
                        requirements=requirements,
                        action='delete_all_mac',
                        conditions=dict(method=['DELETE']))

        path = '/guest/database/mac'
        mapper.connect('router', path, controller=SwitchController,
                        requirements=requirements,
                        action='get_all_mac',
                        conditions=dict(method=['GET']))
        
        # For controller
        path = '/guest/switch/server/port'
        mapper.connect('router', path, controller=SwitchController,
                       requirements=requirements,
                       action='set_server_port',
                       conditions=dict(method=['POST']))

    
    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def datapath_handler(self, ev):
        print "datapath_handler"
        if ev.enter:
            SwitchController.register(ev.dp)
        else:
            SwitchController.unregister(ev.dp)
    

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        SwitchController.packet_in_handler(ev)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        SwitchController.port_status_handler(ev)


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

class Database(object):
    db_path = "/home/jesse/wifi.db.sqlite"
    def __init__(self, *args, **kwargs):
        super(Database, self).__init__(*args, **kwargs)
    
    @classmethod
    def _select(cls, sql):
        try :
            db = sqlite3.connect(cls.db_path)
            cursor = db.execute(sql)
            result = cursor.fetchall() 
        except Exception as err:
            print err
        finally:
            db.close()
        return result

    @classmethod
    def _insert(cls, sql):
        status = True
        details = "success"
        try :
            db = sqlite3.connect(cls.db_path)
            db.execute(sql)
            db.commit()
        except Exception as err:
            details = str(err)
            status = False
        finally:
            db.close()
        return status, details

    @classmethod
    def _delete(cls, sql):
        status = True
        details = "success"
        try :
            db = sqlite3.connect(cls.db_path)
            db.execute(sql)
            db.commit()
        except Exception as err:
            details = str(err)
            status = False
        finally:
            db.close()
        return status, details

    @classmethod
    def add_mac(cls, mac):
        sql = "INSERT INTO guest VALUES (\"" + mac + "\");" 
        return cls._insert(sql)

    @classmethod
    def del_mac(cls, mac):
        sql = "DELETE FROM guest WHERE mac=\"" + mac + "\"" 
        return cls._delete(sql)

    @classmethod
    def delete_all_mac(cls):
        sql = "DELETE FROM guest"
        return cls._delete(sql)

    @classmethod
    def get_all_mac(cls):
        sql = "SELECT mac FROM guest"
        return cls._select(sql)
   
    @classmethod
    def match_mac(cls, mac):
        sql = "SELECT mac FROM guest where mac='" + mac + "'"
        result = cls._select(sql)
        if len(result) == 1:
            return True
        return False


class SwitchController(ControllerBase):
    _SWITCH_LIST = {}
    _LOGGER = None

    def __init__(self, req, link, data, **config):
        super(SwitchController, self).__init__(req, link, data, **config)
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
        except OFPUnknownVersion as message:
            cls._LOGGER.error(str(message), extra=dpid)
            return
        cls._SWITCH_LIST.setdefault(dp.id, switch)
        cls._LOGGER.info('Join as switch.', extra=dpid)

    @classmethod
    def unregister(cls, dp):
        if dp.id in cls._SWITCH_LIST:
            #cls._SWITCH_LIST[dp.id].delete()
            del cls._SWITCH_LIST[dp.id]

            dpid = {'sw_id': dpid_lib.dpid_to_str(dp.id)}
            cls._LOGGER.info('Leave switch.', extra=dpid)

    @classmethod
    def packet_in_handler(cls, ev):
        msg = ev.msg
        dp_id = msg.datapath.id
        if dp_id in cls._SWITCH_LIST:
            switch = cls._SWITCH_LIST[dp_id]
            switch.packet_in_handler(ev)

    @classmethod
    def port_status_handler(cls, ev):
        msg = ev.msg
        dp_id = msg.datapath.id
        if dp_id in cls._SWITCH_LIST:
            switch = cls._SWITCH_LIST[dp_id]
            switch.port_status_handler(ev)

    @rest_command
    def add_mac(self, req):
        rest_param = req.body
        ujson_parm = json.loads(rest_param) if rest_param else {}
        json_parm = ast.literal_eval(json.dumps(ujson_parm))
        macs = json_parm["mac"]

        result = []
        for mac in macs:
            status, details = Database.add_mac(mac)
            result.append({"mac": mac, "status": status, "details": details})
        return result

    @rest_command
    def get_all_mac(self, req):
        macs = Database.get_all_mac()
        result = []
        for m in macs:
            result.append(m[0])
        return result

    @rest_command
    def delete_all_mac(self, req):
        return Database.delete_all_mac()

    @rest_command
    def del_mac(self, req):
        rest_param = req.body
        ujson_parm = json.loads(rest_param) if rest_param else {}
        json_parm = ast.literal_eval(json.dumps(ujson_parm))
        macs = json_parm["mac"]

        result = []
        for mac in macs:
            status, details = Database.del_mac(mac)
            result.append({"mac": mac, "status": status, "details": details})
        return result

    @rest_command
    def set_server_port(self, req):
        print req.body
        rest_param = req.body
        ujson_parm = json.loads(rest_param) if rest_param else {}
        json_parm = ast.literal_eval(json.dumps(ujson_parm))
        dpid = json_parm["dpid"]
        port = json_parm["port"]

        status = SwitchController._SWITCH_LIST[dpid].set_server_port(port)
        if status :
            return status, "success"
        else:
            return status, "failure"

       
# TODO: Update routing table when port status is changed.
class Switch(dict):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    
    def __init__(self, dp, logger):
        super(Switch, self).__init__()
        self.dp = dp
        self.dpid_str = dpid_lib.dpid_to_str(dp.id)
        self.sw_id = {'sw_id': self.dpid_str}
        self.logger = logger
        self.mac_to_port = {}
        self.server_port = [4]

    def set_server_port(self, port):
        self.server_port = port
        return True

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    def add_drop_flow(self, datapath, in_port, src):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_src=haddr_to_bin(src))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=[])
        datapath.send_msg(mod)

    def packet_in_handler(self, ev):


        msg = ev.msg
        print msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src

        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        if msg.in_port not in self.server_port and\
                Database.match_mac(src) == False :
            self.add_drop_flow(datapath, msg.in_port, src)
            return

        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    def port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)