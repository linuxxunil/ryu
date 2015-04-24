import logging
from ryu.controller import event

LOG = logging.getLogger(__name__)



# by jesse
class EventTestItemRequest(event.EventRequestBase):
    def __init__(self, content):
        super(EventTestItemRequest, self).__init__()
        self.dst = 'oftester'
        self.target_version = content["target_version"]
        self.target_dpid = content["target_dpid"]
        self.target_recv_port = content["target_recv_port"]
        self.target_send_port_1 = content["target_send_port_1"]
        self.target_send_port_2 = content["target_send_port_2"]
        self.tester_version = content["tester_version"]
        self.tester_dpid = content["tester_dpid"]
        self.tester_send_port = content["tester_send_port"]
        self.tester_recv_port1 = content["tester_recv_port_1"]
        self.tester_recv_port2 = content["tester_recv_port_2"]
        self.test_item = content["test_item"]

    def __str__(self):
        return 'EventTestItemRequest<src=%s>' % \
            (self.src)
# by jesse
class EventTestItemReply(event.EventReplyBase):
    def __init__(self, dst, status, description, target_dpid):
        super(EventTestItemReply, self).__init__(dst)
        self.status = status
        self.description = description
        self.target_dpid = target_dpid

    def __str__(self):
        return 'EventTestItemReply<dst=%s, interval=%f, interval>' % \
            (self.dst)

class EventTestItemResultRequest(event.EventRequestBase):
    def __init__(self):
        super(EventTestItemResultRequest, self).__init__()
        self.dst = 'oftester'

    def __str__(self):
        return 'EventTestItemResultRequest<src=%s>' % \
            (self.src)
# by jesse
class EventTestItemResultReply(event.EventReplyBase):
    def __init__(self, dst, result, target_dpid, state, test_item):
        super(EventTestItemResultReply, self).__init__(dst)
        self.result = result
        self.target_dpid = target_dpid
        self.state = state
        self.test_item = test_item
    def __str__(self):
        return 'EventTestItemResultReply<dst=%s, interval=%f, interval>' % \
            (self.dst)

class EventTestItemStopRequest(event.EventRequestBase):
    def __init__(self):
        super(EventTestItemStopRequest, self).__init__()
        self.dst = 'oftester'

    def __str__(self):
        return 'EventTestItemStopRequest<src=%s>' % \
            (self.src)
# by jesse
class EventTestItemStopReply(event.EventReplyBase):
    def __init__(self, dst, state):
        super(EventTestItemStopReply, self).__init__(dst)
        self.state = state

    def __str__(self):
        return 'EventTestItemStopReply<dst=%s, interval=%f, interval>' % \
            (self.dst)