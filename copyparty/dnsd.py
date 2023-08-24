# coding: utf-8
from __future__ import print_function, unicode_literals
from socketserver import BaseRequestHandler, ThreadingUDPServer
import logging
import os
import time

from .stolen.dnslib import DNSRecord, QTYPE, RR, TXT, RCODE, CNAME
from .__init__ import TYPE_CHECKING
from .authsrv import VFS
from .bos import bos
from .util import (
    Daemon,
    sanitize_fn,
    vjoin,
    ANYWIN,
    relchk,
    ipnorm
)

if TYPE_CHECKING:
    from .svchub import SvcHub


def handle(self):
    d = self.request[0].strip()
    req = DNSRecord.parse(d)
    ans = answer(req, self.hub, self.client_address)

    self.request[1].sendto(ans.pack(), self.client_address)


def root(reply: DNSRecord, hub):
    r = {x.split("/")[0]: 1 for x in hub.asrv.vfs.all_vols.keys()}
    rs = list(sorted(list(r.keys())))
    for r in rs:
        reply.add_answer(RR)


def answer(req: DNSRecord, hub, ip: str) -> DNSRecord:
    reply = req.reply()
    qname = req.q.qname
    s = qname.idna().split(".")
    s.pop()

    print(s)
    ## TLD must be copyparty
    if s[-1] != "copyparty":
        reply.add_answer(RR(rname=req.q.qname, rtype=QTYPE.TXT, rdata=TXT(b'nah')))
        reply.header.rcode = RCODE.NXDOMAIN
        return reply

    # user auth basically copy-pasted from ftpd.py
    bans = hub.bans
    ip = ipnorm(ip)
    if ip in bans:
        rt = bans[ip] - time.time()
        if rt < 0:
            logging.info("client unbanned")
            del bans[ip]
        else:
            reply.add_answer(RR(rname=req.q.qname, rtype=QTYPE.TXT, rdata=TXT(b'banned')))
            reply.header.rcode = RCODE.REFUSED
            return reply
            
    asrv = hub.asrv
    uname = "*" if s[-2] == "anonymous" else s[-2]
    zs = asrv.iacct.get(asrv.ah.hash(uname), "")
    if zs:
        uname = zs
    
    if not uname or not (asrv.vfs.aread.get(uname)):
        g = hub.gpwd
        if g.lim:
            bonk, ip = g.bonk(ip, uname)
            if bonk:
                logging.warning("client banned: invalid password")
                bans[ip] = bonk
        reply.add_answer(RR(rname=req.q.qname, rtype=QTYPE.TXT, rdata=TXT(b'wrong password')))
        reply.header.rcode = RCODE.REFUSED
        return reply
    
    path = "/" if len(s) == 2 else os.path.join(*s[::-1][2:])

    rd, fn = os.path.split(path)
    if ANYWIN and relchk(rd):
        logging.warning("malicious vpath: %s", path)
        reply.add_answer(RR(rname=req.q.qname, rtype=QTYPE.TXT, rdata=TXT(b'fuck those characters')))
        reply.header.rcode = RCODE.REFUSED
    
    fn = sanitize_fn(fn or "", "", [".prologue.html", ".epilogue.html"])
    vpath = vjoin(rd, fn)
    vfs, rem = hub.asrv.vfs.get(vpath, uname, True, False, False, False)
    if not vfs.realpath:
        reply.add_answer(RR(rname=req.q.qname, rtype=QTYPE.TXT, rdata=TXT(b'nope')))
        reply.header.rcode = RCODE.REFUSED
    
    if not bos.path.isdir(os.path.join(vfs.realpath, rem)):
        reply.add_answer(RR(rname=req.q.qname, rtype=QTYPE.TXT, rdata=TXT(b'no such path')))
        reply.header.rcode = RCODE.NXDOMAIN

    fsroot, vfs_ls1, vfs_virt = vfs.ls(
        rem,
        uname,
        False,
        [[True, False], [False, True]],
    )
    vfs_ls = [x[0] for x in vfs_ls1]
    vfs_ls.extend(vfs_virt.keys())

    vfs_ls.sort()

    for i in vfs_ls:
        i = i.replace(".", "-")
        cname = "{}.{}.copyparty".format(i, s[-2])
        print(cname)
        reply.add_answer(RR(rname=req.q.qname, rtype=QTYPE.NS, rdata=CNAME(cname)))

    return reply
    

class Dnsd(object):

    hub: "SvcHub"

    def handler_factory(self):
        return type("DNSHandler", (BaseRequestHandler, ), {
            "handle": handle,
            "hub": self.hub
        })

    def __init__(self, hub: "SvcHub") -> None:
        self.hub = hub
        self.args = hub.args

        s = []
        if self.args.dns:
            s.append((self.handler_factory(), self.args.dns))
        
        ips = self.args.i
        if "::" in ips:
            ips.remove("::")
            ips.append("0.0.0.0")
        
        for ip in ips:
            for h, args in s:
                Daemon(ThreadingUDPServer((ip, args), h).serve_forever)
