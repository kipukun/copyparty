# coding: utf-8
from __future__ import print_function, unicode_literals
from socketserver import BaseRequestHandler, ThreadingUDPServer

from .stolen.dnslib import DNSRecord, DNSHeader, QTYPE, RR, TXT
from .__init__ import TYPE_CHECKING
from .util import (
    Daemon
)

if TYPE_CHECKING:
    from .svchub import SvcHub


def r(d):
    req = DNSRecord.parse(d)
    reply = DNSRecord(DNSHeader(id=req.header.id, qr=1, aa=1, ra=1), q=req.q)

    qn = str(req.q.qname)
    qt = QTYPE[req.q.qtype]

    if qt != "TXT":
        raise Exception("not implemented: {}".format(qt))
    
    reply.add_answer(RR(rname=qn, rdata=TXT(b'copy.party')))

    return reply.pack()


class DNSHandler(BaseRequestHandler):
    def handle(self):
        d = self.request[0].strip()
        self.request[1].sendto(r(d), self.client_address)
            

class Dnsd(object):
    def __init__(self, hub: "SvcHub") -> None:
        self.hub = hub
        self.args = hub.args

        s = []
        if self.args.dns:
            s.append((DNSHandler, self.args.dns))
        
        ips = self.args.i
        if "::" in ips:
            ips.remove("::")
            ips.append("0.0.0.0")
        
        for ip in ips:
            for h, args in s:
                Daemon(ThreadingUDPServer((ip, args), h).serve_forever)
