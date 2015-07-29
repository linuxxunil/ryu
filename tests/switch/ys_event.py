import logging
from ryu.controller import event

LOG = logging.getLogger(__name__)

# by jesse
class EventTestItemRequest(event.EventRequestBase):
    def __init__(self, content, parse_tests):
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
        self.tester_recv_port_1 = content["tester_recv_port_1"]
        self.tester_recv_port_2 = content["tester_recv_port_2"]
        self.test_item = content["test_item"]
        self.parse_tests = parse_tests

    def __str__(self):
        return 'EventTestItemRequest<src=%s>' % \
            (self.src)

class EventTestItemReply(event.EventReplyBase):
    def __init__(self, dst, result):
        super(EventTestItemReply, self).__init__(dst)
        self.result = result

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

class EventTestItemResultReply(event.EventReplyBase):
    def __init__(self, dst, result):
        super(EventTestItemResultReply, self).__init__(dst)
        self.result = result
        
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

class EventTestItemStopReply(event.EventReplyBase):
    def __init__(self, dst, result):
        super(EventTestItemStopReply, self).__init__(dst)
        self.result = result

    def __str__(self):
        return 'EventTestItemStopReply<dst=%s, interval=%f, interval>' % \
            (self.dst)

class EventCheckLinkRequest(event.EventRequestBase):
    def __init__(self, content):
        super(EventCheckLinkRequest, self).__init__()
        self.dst = 'oftester'
        self.target_version = content["target_version"]
        self.target_dpid = content["target_dpid"]
        self.target_recv_port = content["target_recv_port"]
        self.target_send_port_1 = content["target_send_port_1"]
        self.target_send_port_2 = content["target_send_port_2"]
        self.tester_version = content["tester_version"]
        self.tester_dpid = content["tester_dpid"]
        self.tester_send_port = content["tester_send_port"]
        self.tester_recv_port_1 = content["tester_recv_port_1"]
        self.tester_recv_port_2 = content["tester_recv_port_2"]

    def __str__(self):
        return 'EventCheckLinkRequest<src=%s>' % \
            (self.src)

class EventCheckLinkReply(event.EventReplyBase):
    def __init__(self, dst, result):
        super(EventCheckLinkReply, self).__init__(dst)
        self.result = result

    def __str__(self):
        return 'EventCheckLinkReply<dst=%s, interval=%f, interval>' % \
            (self.dst)

class EventCheckLinkResultRequest(event.EventRequestBase):
    def __init__(self):
        super(EventCheckLinkResultRequest, self).__init__()
        self.dst = 'oftester'

    def __str__(self):
        return 'EventCheckLinkResultRequest<src=%s>' % \
            (self.src)

class EventCheckLinkResultReply(event.EventReplyBase):
    def __init__(self, dst, result):
        super(EventCheckLinkResultReply, self).__init__(dst)
        self.result = result

    def __str__(self):
        return 'EventCheckLinkResultReply<dst=%s, interval=%f, interval>' % \
            (self.dst)

class EventCheckLinkStopRequest(event.EventRequestBase):
    def __init__(self):
        super(EventCheckLinkStopRequest, self).__init__()
        self.dst = 'oftester'

    def __str__(self):
        return 'EventCheckLinkStopRequest<src=%s>' % \
            (self.src)

class EventCheckLinkStopReply(event.EventReplyBase):
    def __init__(self, dst, result):
        super(EventCheckLinkStopReply, self).__init__(dst)
        self.result = result

    def __str__(self):
        return 'EventCheckLinkStopReply<dst=%s, interval=%f, interval>' % \
            (self.dst)
