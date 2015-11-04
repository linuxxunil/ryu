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

import logging
from ryu.controller import event

LOG = logging.getLogger(__name__)


class EventSwitchBase(event.EventBase):
    def __init__(self, switch):
        super(EventSwitchBase, self).__init__()
        self.switch = switch

    def __str__(self):
        return '%s<dpid=%s, %s ports>' % \
            (self.__class__.__name__,
             self.switch.dp.id, len(self.switch.ports))


class EventSwitchEnter(EventSwitchBase):
    def __init__(self, switch):
        super(EventSwitchEnter, self).__init__(switch)


class EventSwitchLeave(EventSwitchBase):
    def __init__(self, switch):
        super(EventSwitchLeave, self).__init__(switch)


class EventPortBase(event.EventBase):
    def __init__(self, port):
        super(EventPortBase, self).__init__()
        self.port = port

    def __str__(self):
        return '%s<%s>' % (self.__class__.__name__, self.port)


class EventPortAdd(EventPortBase):
    def __init__(self, port):
        super(EventPortAdd, self).__init__(port)


class EventPortDelete(EventPortBase):
    def __init__(self, port):
        super(EventPortDelete, self).__init__(port)


class EventPortModify(EventPortBase):
    def __init__(self, port):
        super(EventPortModify, self).__init__(port)


class EventSwitchRequest(event.EventRequestBase):
    # If dpid is None, reply all list
    def __init__(self, dpid=None):
        super(EventSwitchRequest, self).__init__()
        self.dst = 'switches'
        self.dpid = dpid

    def __str__(self):
        return 'EventSwitchRequest<src=%s, dpid=%s>' % \
            (self.src, self.dpid)


class EventSwitchReply(event.EventReplyBase):
    def __init__(self, dst, switches):
        super(EventSwitchReply, self).__init__(dst)
        self.switches = switches

    def __str__(self):
        return 'EventSwitchReply<dst=%s, %s>' % \
            (self.dst, self.switches)


class EventLinkBase(event.EventBase):
    def __init__(self, link):
        super(EventLinkBase, self).__init__()
        self.link = link

    def __str__(self):
        return '%s<%s>' % (self.__class__.__name__, self.link)


class EventLinkAdd(EventLinkBase):
    def __init__(self, link):
        super(EventLinkAdd, self).__init__(link)


class EventLinkDelete(EventLinkBase):
    def __init__(self, link):
        super(EventLinkDelete, self).__init__(link)


class EventLinkRequest(event.EventRequestBase):
    # If dpid is None, reply all list
    def __init__(self, dpid=None):
        super(EventLinkRequest, self).__init__()
        self.dst = 'switches'
        self.dpid = dpid

    def __str__(self):
        return 'EventLinkRequest<src=%s, dpid=%s>' % \
            (self.src, self.dpid)


class EventLinkReply(event.EventReplyBase):
    def __init__(self, dst, dpid, links):
        super(EventLinkReply, self).__init__(dst)
        self.dpid = dpid
        self.links = links

    def __str__(self):
        return 'EventLinkReply<dst=%s, dpid=%s, links=%s>' % \
            (self.dst, self.dpid, len(self.links))


# by jesse : clink request
class EventCLinkRequest(event.EventRequestBase):
    # If dpid is None, reply all list
    def __init__(self, dpid=None):
        super(EventCLinkRequest, self).__init__()
        self.dst = 'switches'
        self.dpid = dpid

    def __str__(self):
        return 'EventCLinkRequest<src=%s, dpid=%s>' % \
            (self.src, self.dpid)

# by jesse : clink response
class EventCLinkReply(event.EventReplyBase):
    def __init__(self, dst, dpid, links):
        super(EventCLinkReply, self).__init__(dst)
        self.dpid = dpid
        self.links = links

    def __str__(self):
        return 'EventLinkReply<dst=%s, dpid=%s, links=%s>' % \
            (self.dst, self.dpid, len(self.links))


# by jesse : slink request
class EventSLinkRequest(event.EventRequestBase):
    # If dpid is None, reply all list
    def __init__(self, dpid=None):
        super(EventSLinkRequest, self).__init__()
        self.dst = 'switches'
        self.dpid = dpid

    def __str__(self):
        return 'EventCLinkRequest<src=%s, dpid=%s>' % \
            (self.src, self.dpid)

# by jesse : slink response
class EventSLinkReply(event.EventReplyBase):
    def __init__(self, dst, dpid, links):
        super(EventSLinkReply, self).__init__(dst)
        self.dpid = dpid
        self.links = links

    def __str__(self):
        return 'EventLinkReply<dst=%s, dpid=%s, links=%s>' % \
            (self.dst, self.dpid, len(self.links))

# by jesse
class EventLLDPRequest(event.EventRequestBase):
    def __init__(self, method, interval = None):
        super(EventLLDPRequest, self).__init__()
        self.dst = 'switches'
        self.method = method
        self.interval = interval
      
    def __str__(self):
        return 'EventLLDPRequest<src=%s>' % \
            (self.src)
# by jesse
class EventLLDPReply(event.EventReplyBase):
    def __init__(self, dst, interval):
        super(EventLLDPReply, self).__init__(dst)
        self.interval = interval

    def __str__(self):
        return 'EventLLDPReply<dst=%s, interval=%f, interval>' % \
            (self.dst, self.interval)